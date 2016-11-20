##ProxychainsProxies

Was tired of getting the reCAPTCHA when browsing through tor.
So why not use other proxies I thought, which might be able to avoid some of those tor-fingerprinting stuff?
The hassle though is looking through proxies, seeing which ones are more shitty than the other ones, adding the "socks4", "http" or "socks5" in front of every entry... 
Yeah, it sux. That's no way to live! That's why this script was created:
 * Gets you the proxies
 * Checks which proxies work
 * Creates a proxychains.conf file



####Note:
By default, it uses random-chain with a depth of 2 and no DNS through the proxy.
This can be changed however in the template.conf file 
