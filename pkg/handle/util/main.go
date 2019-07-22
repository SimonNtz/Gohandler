package util

import (
	"net/http"
	"fmt"
	"encoding/json"
	"io/ioutil"
	"crypto/tls"
	"net/http/httputil"
	"log"
	"github.com/Gohandler/pkg/handle/model"
	"bytes"
)

func SearchType(ttype string, values []model.HandleValue) []model.HandleValue {
	var result []model.HandleValue
	// map the slice element to their 'Type' as the key, duplicate are possible
	for _, v := range values {
		if v.Type == ttype {
			result = append(result, model.HandleValue{Data: v.Data, Index: v.Index})
		}
	}
	return(result)
}

func ResolveGHR(handle string) model.HandleResponse {
	url := fmt.Sprintf("http://38.100.138.180:8000/api/handles/0.NA/%s", handle)
	
	resp, err := http.Get(url)
	if err != nil {
		 panic(err) 
	}

	body, readErr := ioutil.ReadAll(resp.Body)
	if readErr != nil { 
		panic(err) 
	}
	
	var i model.HandleResponse

	berr := json.Unmarshal(body, &i)
	if berr != nil {
		panic("OMG!!")
	}

	return i
}

func ResolveLHS(handle string, ip string, port int) map[string]interface{}{
	url := fmt.Sprintf("http://%s:%d/api/handles/%s", ip, port, handle)
	
	resp, err := http.Get(url)
	if err != nil {
		 panic(err) 
	}

	body, readErr := ioutil.ReadAll(resp.Body)
	if readErr != nil { 
		panic(err) 
	}
	
	var i model.HandleResponse

	berr := json.Unmarshal(body, &i)
	if berr != nil {
		panic("OMG!!")
	}

	var inInterface map[string]interface{}
	inrec, _ := json.Marshal(&i)
    json.Unmarshal(inrec, &inInterface)
	
	return inInterface
}


func PostAuthLHS(sessId string, clientNonce string, signB64 string) bool {
	var body []byte
	var response *http.Response
	var request *http.Request
 
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify : true},
	}
 
	url := "https://156.106.193.160:8011/api/sessions/this"
	request, err := http.NewRequest("PUT", url, nil)
	if err == nil {
		request.Header.Add("Content-Type", "application/json")
		request.Header.Add("Connection", "keep-alive")
		request.Header.Add("Accept", "*/*")
		auths := fmt.Sprintf("Handle sessionID=%q,cnonce=%q,id=%q,type=%q, alg=%q,signature=%q",
							 sessId, clientNonce, "300:0.NA/11.test", "HS_PUBKEY", "SHA256", signB64)
		request.Header.Add("Authorization", auths)
		fmt.Println(request.Header.Get("Authorization"))
		Debug(httputil.DumpRequestOut(request, true))
		response, err = (&http.Client{ Transport: tr}).Do(request)
	}
 
	if err == nil {
		defer response.Body.Close()
		Debug(httputil.DumpResponse(response, true))
		body, err = ioutil.ReadAll(response.Body)
	}
 
	if err != nil {
		log.Fatalf("ERROR: %s", err)
	}
	
	json_body := make(map[string] interface{})
	err = json.Unmarshal(body, &json_body)
	if err != nil {
		log.Fatalf("ERROR: %s", err)
	}
	
	return json_body["authenticated"].(bool)
 }

 /*Add Ip port blob object argument*/

func PostLHS(handle string, site model.Site, sessionId string, object []byte) {
    // var body []byte
    var response *http.Response
    var request *http.Request

    tr := &http.Transport{
        TLSClientConfig: &tls.Config{InsecureSkipVerify : true},
    }

	url := fmt.Sprintf("https://156.106.193.160:8011/api/handles/%s", handle)
	
    request, err := http.NewRequest("PUT", url, bytes.NewBuffer(object))
    if err == nil {
        request.Header.Add("Content-Type", "application/json")
        request.Header.Add("Connection", "keep-alive")
        auths := fmt.Sprintf("Handle sessionID=%q", sessionId)      
        request.Header.Add("Authorization", auths)
        Debug(httputil.DumpRequestOut(request, true))
        response, err = (&http.Client{ Transport: tr}).Do(request)
    }

    if err == nil {
        defer response.Body.Close()
        Debug(httputil.DumpResponse(response, true))
        _, err = ioutil.ReadAll(response.Body)
    }

    if err != nil {
        log.Fatalf("ERROR: %s", err)
    }
}


func PutLHS(handle string, object []byte, ip string, port int, sessionId string) {
    // var body []byte
    var response *http.Response
    var request *http.Request

    tr := &http.Transport{
        TLSClientConfig: &tls.Config{InsecureSkipVerify : true},
    }

    url := fmt.Sprintf("https://%s:%d/api/handles/%s", ip, port, handle)
    request, err := http.NewRequest("PUT", url, bytes.NewBuffer(object))
    if err == nil {
        request.Header.Add("Content-Type", "application/json")
        request.Header.Add("Connection", "keep-alive")
        auths := fmt.Sprintf("Handle sessionID=%q", sessionId)      
        request.Header.Add("Authorization", auths)
        Debug(httputil.DumpRequestOut(request, true))
        response, err = (&http.Client{ Transport: tr}).Do(request)
    }

    if err == nil {
        defer response.Body.Close()
        Debug(httputil.DumpResponse(response, true))
        _, err = ioutil.ReadAll(response.Body)
    }

    if err != nil {
        log.Fatalf("ERROR: %s", err)
    }
}


func Debug(data []byte, err error) {
	if err == nil {
		fmt.Printf("%s\n\n", data)
	} else {
		log.Fatalf("%s\n\n", err)
	}
}


