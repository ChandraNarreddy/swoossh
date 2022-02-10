package storage

import "testing"

func TestPageTokenEndec(t *testing.T) {
	encodedToken := `D_-HBAEC_4gAAQwB_4IAAFb_gQMBAv-CAAEKAQFCAQoAAQRCT09MAQIAAQJCUwH_hAABAUwB_4YAAQFNAf-IAAEBTgEMAAECTlMB_4oAAQROVUxMAQIAAQFTAQwAAQJTUwH_igAAABf_gwIBAQlbXVtddWludDgB_4QAAQoAACn_hQIBARpbXSpkeW5hbW9kYi5BdHRyaWJ1dGVWYWx1ZQH_hgAB_4IAABf_iQIBAQlbXSpzdHJpbmcB_4oAAQwAAEb_iAADAnBrCRV1c2VyI2NoYW5kcmEuYmxvZ2dpbmcAAnNrCRV1c2VyI2NoYW5kcmEuYmxvZ2dpbmcABHR5cGUJBHVzZXIA`
	token, decodingErr := decodePageToken(encodedToken)
	if decodingErr != nil {
		t.Errorf("Token decoding error - %+v", decodingErr)
	}
	encoded, encodingErr := encodeLastEvaluatedKey(token)
	if encodingErr != nil {
		t.Errorf("Token encoding failure - %+v", encodingErr)
	}
	if encoded != encodedToken {
		t.Error("Decoding + encoding did not result in original value")
	}
}
