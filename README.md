# anti-https-censorship
Don't let them know which site you are visiting. This can be used to access some blocked sites in China.

## How it works
It hooks some SSL functions to prevent sending SNI (Server Name Indication) in SSL handshaking. Besides, it use DNS over HTTPS to prevent DNS poisoning.
