// Copyright 2023 WeFuzz Research and Development B.V.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package cmds

import "fmt"

const Version = "v0.9.3"

func Banner() {
	banner := `

   _____ _                                          _              
  / ____| |                                        | |             
 | |    | |__  _ __ ___  _ __   ___  _ __ ___   ___| |_ _ __ _   _ 
 | |    | '_ \| '__/ _ \| '_ \ / _ \| '_ ' _ \ / _ \ __| '__| | | |
 | |____| | | | | | (_) | | | | (_) | | | | | |  __/ |_| |  | |_| |
  \_____|_| |_|_|  \___/|_| |_|\___/|_| |_| |_|\___|\__|_|   \__, |
                                                              __/ |
                                                             |___/ 

`
	fmt.Println(banner)
}
