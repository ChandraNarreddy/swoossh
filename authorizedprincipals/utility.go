package authorizedprincipals

func intersectionAmongStringLists(first []string, second []string) bool {
	if first == nil || second == nil {
		return false
	}
	for _, v := range first {
		for _, w := range second {
			if v == w {
				return true
			}
		}
	}
	return false
}
