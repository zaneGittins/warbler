package misc

import "fmt"

func DisplayBanner() {
	banner := `
 _       __           __    __         
| |     / /___ ______/ /_  / /_  ____
| | /| / / __ / ___/ __ \/ / _ \/ ___/
| |/ |/ / /_/ / /  / /_/ / /  __/ /
|__/|__/\__,_/_/  /_.___/_/\___/_/
Author: Zane Gittins
v0.0.1
`
	fmt.Println(banner)
}
