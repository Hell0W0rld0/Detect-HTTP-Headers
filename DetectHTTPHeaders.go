package main

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:63.0) Gecko/20100101 Firefox/63.0"
)

var secHeaders = []string{"strict-transport-security", "x-content-type-options", "x-frame-options", "x-xss-protection", "x-dns-prefetch-control", "x-download-options", "x-content-security-policy", "Referrer-Policy", "Public-Key-Pins", "Expect-CT"}

func main() {
	if (1 < len(os.Args)) && (len(os.Args) < 3) {
		url := os.Args[1]
		dectectHeaders(url)
		methodDetect(url)
	} else {
		fmt.Println("\x1b[0;35m[+]Usage: DetectHTTPHeaders domain \x1b[0m")
	}
}

func dectectHeaders(url string) {
	fmt.Println(`

                           dMMMMb  dMMMMMP dMMMMMMP dMMMMMP .aMMMb dMMMMMMP 
                          dMP VMP dMP        dMP   dMP     dMP"VMP   dMP    
                         dMP dMP dMMMP      dMP   dMMMP   dMP       dMP     
                        dMP.aMP dMP        dMP   dMP     dMP.aMP   dMP      
                       dMMMMP" dMMMMMP    dMP   dMMMMMP  VMMMP"   dMP       
                                                                            
                        dMP dMP dMMMMMP .aMMMb  dMMMMb  dMMMMMP dMMMMb  .dMMMb 
                       dMP dMP dMP     dMP"dMP dMP VMP dMP     dMP.dMP dMP" VP 
                      dMMMMMP dMMMP   dMMMMMP dMP dMP dMMMP   dMMMMK"  VMMMb   
                     dMP dMP dMP     dMP dMP dMP.aMP dMP     dMP"AMF dP .dMP   
                    dMP dMP dMMMMMP dMP dMP dMMMMP" dMMMMMP dMP dMP  VMMMP"    
                                                                               
								@Allen Zhang
	`)
	fmt.Printf("\x1b[0;35m[!]开始检测目标网站 %s ......\n\x1b[0m", url)
	time.Sleep(time.Second * 5)
	var lack = []string{}
	var allset = []string{}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		panic(err)
	}
	req.Header.Add("User-agent", ua)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	for _, h := range secHeaders {
		if resp.Header.Get(h) == "" {
			switch h {
			case "Public-Key-Pins":
				l := fmt.Sprintf("\x1b[0;31m[-]目标网站缺少 %s [可选设置]\x1b[0m\n", h)
				lack = append(lack, l)
			case "Expect-CT":
				l := fmt.Sprintf("\x1b[0;31m[-]目标网站缺少 %s [可选设置]\x1b[0m\n", h)
				lack = append(lack, l)
			default:
				l := fmt.Sprintf("\x1b[0;31m[-]目标网站缺少 %s \x1b[0m\n", h)
				lack = append(lack, l)
			}

		} else {
			a := fmt.Sprintf("[+]目标网站已设置 %s \n", h)
			allset = append(allset, a)
		}
	}
	CORS := resp.Header.Get("access-control-allow-origin")
	if CORS == "*" {
		fmt.Println("\x1b[0;31m[-]目标网站可能存在CORS安全问题")
	}
	if (resp.StatusCode == 404) || (resp.StatusCode == 500) {
		fmt.Println("\x1b[0;31m[!]目标网站返回404或500错误！")
	} else {
		if len(resp.Cookies()) > 0 {
			if resp.Cookies()[0].HttpOnly {
				cookie := fmt.Sprintf("[+]目标网站已设置 HttpOnly\n")
				allset = append(allset, cookie)
			} else {
				cookie := fmt.Sprintf("\x1b[0;31m[-]目标网站缺少 HttpOnly\n\x1b[0m")
				lack = append(lack, cookie)
			}
		} else {
			fmt.Println("\x1b[0;31m[!]服务端未设置Cookie!\x1b[0m")
		}

	}

	fmt.Print(strings.Join(allset, ""))
	fmt.Print(strings.Join(lack, ""))

}

func methodDetect(url string) {
	req, err := http.NewRequest("OPTIONS", url, nil)
	if err != nil {
		fmt.Println("请求目标网站失败！", err)
	}
	req.Header.Add("User-agent", ua)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	method := resp.Header.Get("Allow")
	if method == "" {
		fmt.Println("\x1b[0;31m[-]目标网站已经禁止探测HTTP方法！\x1b[0m")
	} else {
		fmt.Printf("[+]目标网站支持 %s 方法\n", method)
	}

}
