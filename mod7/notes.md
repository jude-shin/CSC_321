- statistics->protocol hierarchy 
- decrypt traffic first, because http may be initially encrypted
- TCP Application Data: will be encrypted stuff

- hints:
- there is an RSA key you need to find
    - preferences -> RSA Keys
    - load the private key file
    - Wireshark will automatically decrypt the traffic

- Once you decrypt the traffic, you should look for the following:
    - Restart the wireshark session to decrypt the session
    - HTTP 200 OK packets (text/html)
        - buttons on the bottom will show a decrypted tls from the straight bytes

- you can search for things in the query bar
    - i.e. "smtp"

- analyze -> follow -> TCP stream
    - reassembles the "jumbled" tcp stream (and decrypts at the same time if possible?)
    - then you can look at the traffic in more detail


