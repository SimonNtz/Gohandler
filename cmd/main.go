 
 package main

 import (
	 "fmt"
	 "encoding/json"
	//  "github.com/Gohandler/pkg/handle/model"
	 "github.com/Gohandler/pkg/handle/helper"
	 "github.com/Gohandler/pkg/handle/util"
	//  "errors"
 )
 
 func main() { 
	//hdl := "11.test/smart-consent/cc/00"
	//hdl := "11.test/smart-consent/run0/users/Z6AXNYSHBAN2GI4AITYZKBDOWUMYBT3Q"


	_, sess :=  helper.GetSessionId("11.test")
	// sess := model.Session{Id:"18gn71xoqdz06jjklo28zbc58", Nonce: "6Gd/ry4WCw5+YOGh6tkySA=="}
	keypath := "C:/Users/noetzlin/Documents/DOA/GO/admpriv.pem"
	cnonce, sign := helper.ChallengeSite(keypath, sess)
	if ! util.PostAuthLHS(sess.Id, cnonce, sign) {
		fmt.Printf("Authentication to handle system failed.")
	}
	
	h  := json.RawMessage(`[{"index": 999, "type": "tests", "data": {"value":"PREFIX_TEST", "format":"string"}}]`)
	var hdl []byte
    hdl, err := json.MarshalIndent(&h, "", "\t")
    if err != nil {
		fmt.Println("error:", err)
    }

	//hdl := "11.test/smart-consent/cc/00"
	//hdl := "11.test/smart-consent/run0/users/Z6AXNYSHBAN2GI4AITYZKBDOWUMYBT3Q"

	//_, sess :=  helper.GetSessionId("11.test")
    //sess := model.Session{Id:"18gn71xoqdz06jjklo28zbc58", Nonce: "6Gd/ry4WCw5+YOGh6tkySA=$
	//keypath := "C:/Users/noetzlin/Documents/DOA/GO/admpriv.pem"
	//cnonce, sign := helper.ChallengeSite(keypath, sess)
	//if ! util.PostAuthLHS(sess.Id, cnonce, sign) {
	//   fmt.Printf("Authentication to handle system failed.")
	//rep := util.ResolveLHS(hdl, "156.106.193.160", 8011)
	//fmt.Println("%+v\n", rep)
	
	// SIGNATURE PROCESS
	//sign, _:=  helper.SignHandle("11.test",
	//      hdl,
	//      rep,
	//        "/home/simon/admpriv.pem")

	//hdlObj := fmt.Sprintf(`[{"index": 400 , "type": %s, "data": {"value":%q, "format":"string"}}]`,
	//                                                              "HS_SIGNATURE", string(sign))
	//util.PutLHS(hdl+"?index=various", []byte(hdlObj), "156.106.193.160", 8011, "he15rxhkp1561irkno$

	// VERIFY PROCESS
	//signatureHdl := helper.GetHandleSign(rep)
	//helper.VerifyHandle(signatureHdl, "/home/simon/admpub.pem")
}

