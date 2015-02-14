README FOR REVERSER v1.5 TOOL

NAME : REVERSER.pl
DESC : is a search tool that allows you to use an IP address or domain name to identify all the areas currently hosted on a 
server with multiple and various 
technical services.
 AUTHOR: Alexcerus HR

INSTRUCTIONS :
1) perl Reverser.pl -h
2) perl Reverser
3) An EXEMPLE  : perl Reverser.pl -t www.target.com -o result.txt
4) Full options :
  
-t, --target            For server or Hostname IP
   -c, --check             For Checking extracted domains that are in the same IP address to eleminate cached/old records
   -b, --bing              Save Bing search results to txt File
       --list              List current supported Reverse Ip Lookup websites 
       --print             Display results
       --timeout=SECONDS   Seconds to wait before timeout connection (default 30)
       --user-agent        Specify User-Agent value to send in HTTP requests
       --proxy             To use a Proxy
       --proxy-auth        Proxy authentication information (user:password).
   -o, --output=FILE       Save results to a file (default IP.txt)
   -h, --help              This shity message
   -v, --verbose           Print more informations

   Threads:
   --threads=THREADS       Maximum number of concurrent IP checks (default 1) require --check

REVERSER  written in perl and relies on many websites to conduct research:
Ewhois.com,Viewdns.info,Yougetsignal.com,Myiptest.com,Ip-adress.com,DNStrails.com,My-ip-neighbors.com
Domainsbyip.com,Bing.com,Whois.WebHosting.info,Robtex.com,Tools.web-max.ca,Sameip.org

Greetz;
Alexcerus ~