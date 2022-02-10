package httpserver

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	APIAuthHeaderVer1Prefix               = "v1-hmac-sha256"
	APIAuthHeaderVer1CredentialPrefix     = "Credential="
	APIAuthHeaderVer1SignedHeadersPrefix  = "SignedHeaders="
	APIAuthHeaderVer1SignatureValuePrefix = "Signature="
)

func GenerateSignatureHeader_v1(r *http.Request, creds ApiKeyCreds, headersToSign []string) (*string, error) {
	time := strconv.FormatInt(time.Now().Unix(), 10)
	credentialEntry := APIAuthHeaderVer1Prefix + " " + APIAuthHeaderVer1CredentialPrefix
	credentialEntry = credentialEntry + creds.ApiKeyID + "/" + time

	var loweredHeadersToSign []string
	for _, v := range headersToSign {
		loweredHeadersToSign = append(loweredHeadersToSign, strings.ToLower(v))
	}
	sort.Strings(loweredHeadersToSign)

	var signedHeadersList []string
	var canonicalHeaders string
	for _, p := range loweredHeadersToSign {
		for k, v := range r.Header {
			if p == strings.ToLower(k) {
				signedHeadersList = append(signedHeadersList, p)
				var headersValue string
				for n, each := range v {
					headersValue = headersValue + each
					if n < len(v)-1 {
						headersValue = headersValue + "; "
					}
				}
				canonicalHeaders = canonicalHeaders + p + ":" + headersValue + "\n"
				break
			}
		}
	}
	signedHeaders := strings.Join(signedHeadersList, "; ")

	path := r.URL.Path
	if path == "" {
		path = "/"
	}
	canonicalPath := strings.ReplaceAll(url.PathEscape(path), "%2F", "/")

	var canonicalQuery string
	queryMap := r.URL.Query()
	queryMapKeys := make([]string, 0)
	for k, _ := range queryMap {
		queryMapKeys = append(queryMapKeys, k)
	}
	sort.Strings(queryMapKeys)
	for i, v := range queryMapKeys {
		vals := queryMap[v]
		if len(vals) == 0 {
			canonicalQuery = canonicalQuery + url.PathEscape(v)
			canonicalQuery = canonicalQuery + "="
			canonicalQuery = canonicalQuery + ""
		} else {
			sort.Strings(vals)
			for n, each := range vals {
				canonicalQuery = canonicalQuery + url.PathEscape(v)
				canonicalQuery = canonicalQuery + "="
				val := strings.ReplaceAll(url.PathEscape(each), "=", "%3D")
				canonicalQuery = canonicalQuery + val
				if n < len(vals)-1 {
					canonicalQuery = canonicalQuery + "&"
				}
			}
		}
		if i < len(queryMapKeys)-1 {
			canonicalQuery = canonicalQuery + "&"
		}
	}

	bodyReader := http.MaxBytesReader(nil, r.Body, 1024)
	body, bodyReadErr := ioutil.ReadAll(bodyReader)
	if bodyReadErr != nil {
		log.Printf("Error reading request body: %v", bodyReadErr)
		return nil, fmt.Errorf("Error reading request body: %v", bodyReadErr)
	}
	r.Body = ioutil.NopCloser(bytes.NewBuffer(body))
	bodySum := sha256.Sum256(body)
	hashedPayload := strings.ToLower(hex.EncodeToString(bodySum[:]))

	canonicalRequest :=
		r.Method + "\n" +
			canonicalPath + "\n" +
			canonicalQuery + "\n" +
			canonicalHeaders + "\n" +
			signedHeaders + "\n" +
			hashedPayload
	CanonicalRequestSum := sha256.Sum256([]byte(canonicalRequest))
	hashedCanonicalRequest := strings.ToLower(hex.EncodeToString(CanonicalRequestSum[:]))

	signingString :=
		APIAuthHeaderVer1Prefix + "\n" +
			time + "\n" +
			hashedCanonicalRequest

	timeScopedMacKey := hmac.New(sha256.New, creds.ApiKey).Sum([]byte(time))
	signature := hex.EncodeToString(hmac.New(sha256.New, timeScopedMacKey).Sum([]byte(signingString)))
	signatureHeader := credentialEntry + "," +
		APIAuthHeaderVer1SignedHeadersPrefix + signedHeaders + "," +
		APIAuthHeaderVer1SignatureValuePrefix + signature
	return &signatureHeader, nil
}

func ValidateSignature_v1(r *http.Request, creds []*ApiKeyCreds, authSansVersion string, during time.Time, forPeriodInSecs int64) (bool, *string, error) {
	authSansVersion = strings.TrimSpace(authSansVersion)
	authParts := strings.Split(authSansVersion, ",")
	if len(authParts) != 3 {
		log.Print("Missing components in the auth header")
		return false, nil, fmt.Errorf("Missing components in auth header")
	}

	credentialEntry := authParts[0]
	credentialEntry = strings.TrimSpace(credentialEntry)
	if !strings.HasPrefix(credentialEntry, APIAuthHeaderVer1CredentialPrefix) {
		log.Printf("Credential prefix is not present in the auth header value")
		return false, nil, fmt.Errorf("Auth Header is invalid")
	}
	timeScopedKeyID := strings.TrimPrefix(credentialEntry, APIAuthHeaderVer1CredentialPrefix)
	if len(strings.Split(timeScopedKeyID, "/")) != 2 {
		log.Printf("Credential is not valid")
		return false, nil, fmt.Errorf("Credential is not specified correctly in Auth Header")
	}
	signedTime := strings.Split(timeScopedKeyID, "/")[1]
	signedTimeInt, convErr := strconv.Atoi(signedTime)
	if convErr != nil {
		log.Print("Signed time in credential scope is not a valid timestamp")
		return false, nil, fmt.Errorf("Signed time in credential scope is not a valid timestamp")
	}
	validAfter := during.Unix() - forPeriodInSecs
	validBefore := during.Unix()

	if int64(signedTimeInt) > validBefore || int64(signedTimeInt) < validAfter {
		log.Print("The credential is scoped for an expired or a future timestamp")
		return false, nil, fmt.Errorf("The credential is scoped for an expired or a future timestamp")
	}
	keyID := strings.Split(timeScopedKeyID, "/")[0]

	var key []byte
	for _, v := range creds {
		if v.ApiKeyID == keyID {
			key = v.ApiKey
			break
		}
	}
	if key == nil {
		log.Printf("Credential passed in auth header is not valid")
		return false, nil, fmt.Errorf("Credential not valid")
	}

	signature := authParts[2]
	signature = strings.TrimSpace(signature)
	if !strings.HasPrefix(signature, APIAuthHeaderVer1SignatureValuePrefix) {
		log.Printf("Signature value not present in the auth header value")
		return false, nil, fmt.Errorf("Auth Header is invalid")
	}
	signature = strings.TrimPrefix(signature, APIAuthHeaderVer1SignatureValuePrefix)

	signedHeaders := authParts[1]
	signedHeaders = strings.TrimSpace(signedHeaders)
	if !strings.HasPrefix(signedHeaders, APIAuthHeaderVer1SignedHeadersPrefix) {
		log.Printf("Signed Headers not present in the auth header value")
		return false, nil, fmt.Errorf("Auth Header is invalid")
	}
	signedHeaders = strings.TrimPrefix(signedHeaders, APIAuthHeaderVer1SignedHeadersPrefix)
	signedHeadersList := strings.Split(signedHeaders, "; ")
	sort.Strings(signedHeadersList)
	var canonicalHeaders string
	for _, signedHeader := range signedHeadersList {
		signedHeader = strings.TrimSpace(signedHeader)
		match := false
		for k, v := range r.Header {
			if strings.ToLower(k) == signedHeader {
				var headersValue string
				for n, each := range v {
					headersValue = headersValue + each
					if n < len(v)-1 {
						headersValue = headersValue + "; "
					}
				}
				canonicalHeaders = canonicalHeaders + signedHeader + ":" + headersValue + "\n"
				match = true
				break
			}
		}
		if !match {
			log.Printf("One of the signed headers is not found in the request")
			return false, nil, fmt.Errorf("One of the signed headers is not found in the request")
		}
	}

	path := r.URL.Path
	if path == "" {
		path = "/"
	}
	canonicalPath := strings.ReplaceAll(url.PathEscape(path), "%2F", "/")

	var canonicalQuery string
	queryMap := r.URL.Query()
	queryMapKeys := make([]string, 0)
	for k, _ := range queryMap {
		queryMapKeys = append(queryMapKeys, k)
	}
	sort.Strings(queryMapKeys)
	for i, v := range queryMapKeys {
		vals := queryMap[v]
		if len(vals) == 0 {
			canonicalQuery = canonicalQuery + url.PathEscape(v)
			canonicalQuery = canonicalQuery + "="
			canonicalQuery = canonicalQuery + ""
		} else {
			sort.Strings(vals)
			for n, each := range vals {
				canonicalQuery = canonicalQuery + url.PathEscape(v)
				canonicalQuery = canonicalQuery + "="
				val := strings.ReplaceAll(url.PathEscape(each), "=", "%3D")
				canonicalQuery = canonicalQuery + val
				if n < len(vals)-1 {
					canonicalQuery = canonicalQuery + "&"
				}
			}
		}
		if i < len(queryMapKeys)-1 {
			canonicalQuery = canonicalQuery + "&"
		}
	}

	bodyReader := http.MaxBytesReader(nil, r.Body, 1024)
	body, bodyReadErr := ioutil.ReadAll(bodyReader)
	if bodyReadErr != nil {
		log.Printf("Error reading request body: %v", bodyReadErr)
		return false, nil, fmt.Errorf("Error reading request body: %v", bodyReadErr)
	}
	r.Body = ioutil.NopCloser(bytes.NewBuffer(body))
	bodySum := sha256.Sum256(body)
	hashedPayload := strings.ToLower(hex.EncodeToString(bodySum[:]))

	canonicalRequest :=
		r.Method + "\n" +
			canonicalPath + "\n" +
			canonicalQuery + "\n" +
			canonicalHeaders + "\n" +
			signedHeaders + "\n" +
			hashedPayload
	CanonicalRequestSum := sha256.Sum256([]byte(canonicalRequest))
	hashedCanonicalRequest := strings.ToLower(hex.EncodeToString(CanonicalRequestSum[:]))

	signingString :=
		APIAuthHeaderVer1Prefix + "\n" +
			signedTime + "\n" +
			hashedCanonicalRequest

	timeScopedMacKey := hmac.New(sha256.New, key).Sum([]byte(signedTime))
	counterSignature := hex.EncodeToString(hmac.New(sha256.New, timeScopedMacKey).Sum([]byte(signingString)))

	if !hmac.Equal([]byte(signature), []byte(counterSignature)) {
		return false, nil, nil
	}
	return true, &keyID, nil
}
