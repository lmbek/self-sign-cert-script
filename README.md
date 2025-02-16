# Self Sign Cert Script (TLS certificate using ECDSA)
Please note on windows this program adds the self-signed key into the windows certification store. If this behavior is not wished, just remove that part.


## How to run
To generate a localhost certificate run

    go run .

## How to test (lazy system testing)
To test it modify the main.go and certificate.go by: <br/>
1) first flip the if statemaent <br/>
2) second uncomment the embeds inside certificate_windows.go <br/>
if you don't uncomment the embeds this err will come: <br/>
selfsigning failed: failed to load embedded TLS certificate and key: tls: failed to find any PEM data in certificate input <br/>
