package helper

import (
	"fmt"
	"reflect"
	"strings"
	"net/http"
	"net/http/httputil"
	"io/ioutil"
	"log"
	"time"
	"github.com/SermoDigital/jose/jws"
	"crypto/tls"
	 "encoding/json"
	_ "encoding/base64"
	"github.com/mitchellh/mapstructure"
	"github.com/Gohandler/pkg/handle/model"
	"github.com/Gohandler/pkg/handle/util"
	"github.com/Gohandler/pkg/cryptogen"
	"github.com/SermoDigital/jose/crypto"
	"crypto/sha256"
	"strconv"
)

func GetSite(handle string) model.Site {
	sites := []model.Site{}
	
	if resp := util.ResolveGHR(handle); resp.ResponseCode == 1 {
		siteArray := util.SearchType("HS_SITE", resp.Values)
		for _, v :=  range siteArray {
			s := &model.Site{}
			FillStructSite(v.Data.Value.(map[string]interface{}), s)
			sites = append(sites, *s)
		}
	
	} else {
		fmt.Printf("Handle not resolved. Error code %d\n", resp.ResponseCode)
	}
	/* List all of them */
	fmt.Printf("LHS %q has %d sites:\n", handle, len(sites))
	
	myEndpoint := sites[0]
	fmt.Printf("  -default HTTP endpoint: (%s, %d)\n", myEndpoint.Servers.Address, myEndpoint.Servers.Interfaces.Port)
	return(myEndpoint) 
}

func FillStructSite(data map[string]interface{}, result interface{}) {
	t := reflect.ValueOf(result).Elem()
	for k, v := range data {
		valforfield := t.FieldByName(strings.Title(k))
		if valforfield.IsValid() {
			
			switch v.(type) {
			
			case []interface{}:
				
				switch k {
				case "servers":
					// fmt.Printf("%d server(s) found\n", len(v.([]interface{})))
					temp := v.([]interface{})[0]
					server := &model.Blob{}
					FillStructSite(temp.(map[string]interface{}), server)
					valforfield.Set(reflect.ValueOf(*server))
				case "interfaces":
					// fmt.Printf("%d interface(s) found\n", len(v.([]interface{})))
					for _, v := range v.([]interface{}) {
						var intfc model.Interface
						mapstructure.Decode(v.(map[string]interface{}), &intfc)
						if intfc.Protocol == "HTTP" {
							valforfield.Set(reflect.ValueOf(intfc))
						}
					}
				}
			default	:
				valforfield.Set(reflect.ValueOf(v))
			}
		}
	}
}

func GetSessionId(handle string) (model.Blob, model.Session) {

	myServer := GetSite(handle).Servers
	ip 		:= myServer.Address
	port 	:= myServer.Interfaces.Port

	if (ip == "") || (port == 0) {
		fmt.Printf("Can't get LHS endpoint.")
		return model.Blob{}, model.Session{}
	}

    var body []byte
    var response *http.Response
    var request *http.Request

    tr := &http.Transport{
        TLSClientConfig: &tls.Config{InsecureSkipVerify : true},
    }

    url := fmt.Sprintf("https://%s:%d/api/sessions", ip, port)
    request, err := http.NewRequest("POST", url, nil)
    if err == nil {
        request.Header.Add("Content-Type", "application/json")
        util.Debug(httputil.DumpRequestOut(request, true))
        response, err = (&http.Client{ Transport: tr}).Do(request)
    }

    if err == nil {
        defer response.Body.Close()
        util.Debug(httputil.DumpResponse(response, true))
        body, err = ioutil.ReadAll(response.Body)
    } else {
        log.Fatalf("ERROR: %s", err)
    }

	var sess model.Session
	
	err = json.Unmarshal(body, &sess)
	if err != nil {
		fmt.Println(err)
	}
	
	return myServer, sess
 }


 func ChallengeSite(keypath string, sess model.Session) (cnonce string, sign string) {
	clientNonce := cryptogen.ClientNonce(16)
    key := cryptogen.LoadKeyFile(keypath)
    signPlain := cryptogen.DecodeB64(sess.Nonce) + string(clientNonce[:])
	signRSA := cryptogen.SignMessage(signPlain, key)
	
	return cryptogen.EncodeB64(clientNonce), cryptogen.EncodeB64([]byte(signRSA))
 }

/* Replication of the official The HANDLE.NET software signing tool using Javascript Object Signing and Encryption (JOSE) */

type HandleValueClaim struct {
	Alg   		string      `json:"alg"`
	Digests 	[]Digest 	`json:"digests"`
  }
  
type Digest struct {
	Index		int     `json:"index"`
	Digest	string		`json:"digest"`
}

func SignHandle(issuer string, handle string, handleValues map[string]interface{}, privkeyf string) ([]byte, []byte){

	claims := jws.Claims{}
	hdlValClm := HandleValueClaim{ Alg: "SHA-256",}
	
	for _, handleValue := range handleValues["values"].([]interface{}) {
		mappedValue := handleValue.(map[string]interface{})
		if idx := int(mappedValue["index"].(float64)); idx != 400 {
			digest := Digest {
				Index: 	idx,
				Digest: HashHandleValues(mappedValue),
			}
			hdlValClm.Digests = append(hdlValClm.Digests, digest)
		}
	}	
	
	claims.Set("digests", hdlValClm.Digests)
	//Check relation with ADMIN index type
	expires := time.Now().Add(time.Duration(15) * time.Hour * 24)
	claims.SetIssuer(issuer)
	claims.SetSubject(fmt.Sprintf("0.NA/%s", handle))
	claims.SetExpiration(expires)
	claims.SetIssuedAt(time.Now())
	
	jwt := jws.NewJWT(claims, crypto.SigningMethodRS256)
	privkey := cryptogen.LoadKeyFile(privkeyf)
	s, _ := jwt.Serialize(privkey)

	claimJSON, _ := claims.MarshalJSON()
	return s, claimJSON
}


/* NEED ENHANCEMENT */
func VerifyHandle(accessToken []byte, pubkeyf string) bool {
	bytes, err := ioutil.ReadFile(pubkeyf)
	if err != nil {
	  panic(err)
	}
	rsaPublic, err := crypto.ParseRSAPublicKeyFromPEM(bytes)
	if err != nil {
	  panic(err)
	}
	// pubkey := cryptogen.LoadKeyFile2(pubkeyf)
	// fmt.Printf("%s \n", pubkey)

	jwt, err := jws.ParseJWT(accessToken)
	if err != nil {
		panic(err)
	}
	// _ = pubkey
	// _ = jwt

	if err = jwt.Validate(rsaPublic, crypto.SigningMethodRS256); err != nil {
		panic(err)
	}

	return true
}


func HashHandleValues(rawVal map[string] interface{}) string{
	var hdlVal []byte
	for key, val := range rawVal {
		fmt.Printf("%q\n", key)
		switch key {
		case "data":
			dataJson, err := json.Marshal(&val)
			if err != nil {
				panic(err)
			}
			hdlVal = append(hdlVal, dataJson...)
		case "ttl" :
			ttlStr := strconv.FormatInt(int64(val.(float64)), 10)
			hdlVal = append(hdlVal, []byte(ttlStr)...)
		case "index":
			_ = val	
		default :
			hdlVal = append(hdlVal, []byte(val.(string))...)
		}
	}
	h := sha256.New()
	h.Write(hdlVal)
	
	return fmt.Sprintf("%x", h.Sum(nil))
}


func GetHandleSign(rep map[string]interface{}) []uint8{
	var  hdl model.HandleResponse
	err := mapstructure.Decode(rep, &hdl)
	if err != nil {
		panic(err)
	}

	var sign []byte
	for _, v := range hdl.Values {
		if v.Type == "HS_SIGNATURE" {
			sign = []byte(v.Data.Value.(string))
		} 
	}
	return sign
}

func GetHandleType(rep map[string]interface{}, mytype string) map[string]interface {}{
	var  hdl model.HandleResponse
	err := mapstructure.Decode(rep, &hdl)
	if err != nil {
		panic(err)
	}

	var data map[string]interface{}
	for _, v := range hdl.Values {
		if v.Type == mytype {
			data = map[string]interface{}{"Value": v.Data.Value, "Format": v.Data.Format,}
		} 
	}
	return data
}


// 	fmt.Println(claims)
//  }
//  func main() { 
// 	// fmt.Println(GetSessionId("11.test"))
// 	sess := model.Session{Id:"ftjwcwc6qsbg1mbko146l02bu", Nonce: "6Gd/ry4WCw5+YOGh6tkySA=="}
// 	// keypath := "C:/Users/noetzlin/Documents/DOA/GO/admpriv.pem"
// 	// cnonce, sign := ChallengeSite(keypath, sess)
// 	// util.PostAuthLHS(sess.Id, cnonce, sign)
// 	h  := json.RawMessage(`[{"index": 209, "type": "HS_TEST", "data": {"value":"Golang-Testing", "format":"string"}}]`)
// 	var hdl []byte
//     hdl, err := json.MarshalIndent(&h, "", "\t")
//     if err != nil {
// 		fmt.Println("error:", err)
//     }
// 	util.PutLHS("11.test/gohandler", hdl, sess.Id)
// }