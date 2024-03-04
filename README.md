**xk6-cognito-srp**
An example module for https://k6.io/ to get a cognito access token using USER_SRP_AUTH flow.

**
Pre-built binaries**

go install go.k6.io/xk6/cmd/xk6@latest

xk6 build master  --with github.com/OS-jyothikaspa/xk6-cognito-srp

This will generage a k6 executable in the current folder,  use the executable to run the k6 scripts.

Linux : 
./k6 run "script_name"


Windows:
./k6.exe run "script_name"

