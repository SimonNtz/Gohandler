package model

type HandleResponse struct {
	ResponseCode 	int `json:"responseCode"`
	Handle 		 	string `json:"handle"`
	Values 			[]HandleValue `json:"values"`
}

type HandleValue struct {
	Index int `json:"index"`
	Type string  `json:"type"`
	Data HandlePayload `json:"data"`
	Ttl int `json:"ttl"`
	Timestamp string `json:"timestamp"`
}

type HandlePayload struct {
	Value interface{} `json:"value"`
	Format string `json:"format"`
}

type Site struct {
	PrimarySite 		bool 				`json:"primarySite"`
	MultiPrimary 		bool 				`json:"multiPrimary"`
	Servers 			Blob				`json:"servers"`
}

type Blob struct {
	Interfaces 	Interface					`json:"interfaces"`
	Address 		string					`json:"address"`
	// PublicKey struct {		
	// 	Format 		string 					`json:"format"`
	// 	Value      	map[string]string   	`json:"value"`
	// }   
}

type Interface struct {			
	Protocol 	string						`json:"protocol"`
	Port	  	int 						`json:"port"`
}		

type Session struct {
	Id 		string 			`json:"sessionId"`
	Nonce	string 			`json:"nonce"`
}