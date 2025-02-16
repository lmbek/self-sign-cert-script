# Self Sign Cert Script (TLS certificate using ECDSA)

## How to run
To generate a localhost certificate run

    go run .

## How to test (lazy system testing)
To test it modify the main.go and certificate.go by: <br/>
1) first flip the if statemaent <br/>
2) second uncomment the embeds inside certificate_windows.go <br/>
if you don't uncomment the embeds this err will come: <br/>
selfsigning failed: failed to load embedded TLS certificate and key: tls: failed to find any PEM data in certificate input <br/>
