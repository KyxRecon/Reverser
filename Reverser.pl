#!/usr/bin/env perl
# Reverser - Reverse IP Tool v1.5
# By : Alexcerus HR

print <<EOD; 

           ;               ,           
         ,;                 '.         
        ;:                   :;         
       ::                     ::       
       ::                     ::       
       ':                     :         
        :.                    :         
     ;' ::                   ::  '      
    .'  ';                   ;'  '.     
   ::    :;                 ;:    ::    
   ;      :;.             ,;:     ::   
   :;      :;:           ,;"      ::   
   ::.      ':;  ..,.;  ;:'     ,.;:   
    "'"...   '::,::::: ;:   .;.;""'     
        '"""....;:::::;,;.;"""         
    .:::.....'"':::::::'",...;::::;.   
   ;:' '""'"";.,;:::::;.'""""""  ':;   
  ::'         ;::;:::;::..         :;   
 ::         ,;:::::::::::;:..       :: 
 ;'     ,;;:;::::::::::::::;";..    ':. 
::     ;:"  ::::::"""'::::::  ":     :: 
 :.    ::   ::::::;  :::::::   :     ; 
  ;    ::   :::::::  :::::::   :    ;   
   '   ::   ::::::....:::::'  ,:   '   
    '  ::    :::::::::::::"   ::       
       ::     ':::::::::"'    ::       
       ':       """""""'      ::       
        ::                   ;:         ~ Reverser - Reverse IP Tool v1.5
        ':;                 ;:"                 ~ By : Alexcerus HR
          ';              ,;'           
            "'           '" 


 
EOD

use LWP::Simple;
use Socket qw(inet_aton);
use Getopt::Long;

# check missing modules...
my @Modules = ("threads","LWP::ConnCache","HTTP::Cookies");
#py class
#class reverse(object):
#	def run(self, target):
#		print ""
#		if target.startswith("http://"):
#			target = target.replace("http://", "")
#		elif target.startswith("https://"):	
#			target = target.replace("https://", "")

foreach my $module (@Modules)
{
	my $can = eval "use $module;1;";
    if ($can && $module =~ /threads/)
	{
		# Do processing using threads
		$thread_support = 1;
    }
#		url = "http://viewdns.info/reverseip/?host=%s&t=1" % (target)
#
#		try:
#			opener = urllib2.build_opener()
#			opener.addheaders = [('User-agent','Mozilla/5.0 (Mobile; rv:14.0) Gecko/14.0 Firefox/14.0')]
#			response = opener.open(url)
#			data = response.read()
#			comp = re.compile("<tr><td>\S+</td><td")
#			baglantilar = comp.findall(data)
#
#			for i in baglantilar:
#				i = i.replace("<tr><td>", "").replace("</td><td", "")
#
#				if i.startswith("http://"):
#					pass
#				else:
#					i = "http://"+i	
#
#				if "Domain" not in i:
#					print i	
	elsif(!$can && $module =~ /threads/)
	{
		# Do it without using threads
		$thread_support = 0;
    }
	# The module isn't there
	if ($@ =~ /Can't locate/) {
		die "\n[!!] it seems that some modules are missing...:\n".$@."\n";
	}
}

my $b = $0;
$b =~ s/.*\///;
sub usage {
    print <<HELP;
Usage: perl $b [OPTIONS]
Available options:
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

HELP
    exit;
}

my %SERV = (
	Myipneighbors =>{
		SITE	=>	"My-ip-neighbors.com",
		URL		=>	"http://www.my-ip-neighbors.com/?domain=%s",
		REGEX	=>	'<td class="action"\starget="\_blank"><a\shref="http\:\/\/whois\.domaintools\.com\/(.*?)"\starget="\_blank"\sclass="external">Whois<\/a><\/td>',
	},
	Yougetsignal =>{
		SITE	=>	"Yougetsignal.com",
		DATA	=>	'remoteAddress',
		URL		=>	"http://www.yougetsignal.com/tools/web-sites-on-web-server/php/get-web-sites-on-web-server-json-data.php",
		SP		=>	'Yougetsignal()',
	},
	Myiptest =>{
		SITE	=>	"Myiptest.com",
		URL		=>	"http://www.myiptest.com/staticpages/index.php/Reverse-IP/%s",
		REGEX	=>	"<td style='width:200px;'><a href='http:\/\/www\.myiptest\.com\/staticpages\/index\.php\/Reverse-IP\/.*?'>(.*?)<\/a><\/td>",
	},
	WebHosting =>{
		SITE	=>	"Whois.WebHosting.info",
		URL		=>	"http://whois.webhosting.info/%s?pi=%s&ob=SLD&oo=DESC",
		HEAVY	=>	1,
		SP		=>	'Whoiswebhosting()',
	},
	Domainsbyip =>{
		SITE	=>	'Domainsbyip.com',
		URL		=>	'http://domainsbyip.com/%s/', 
		REGEX	=>	'<li class="site.*?"><a href="http\:\/\/domainsbyip.com\/domaintoip\/(.*?)/">.*?<\/a>',
	},
# final code py
#		except:
#			print "Something's went wrong .."
#			pass
#
#
#if __name__ == '__main__':
#	a = raw_input("\n\t Target : ")
#	reverse().run(a)
#

	Ipadress =>{
		SITE	=>	"Ip-adress.com",
		URL		=>	"http://www.ip-adress.com/reverse_ip/%s",
		REGEX	=>	'<td style\=\"font\-size\:8pt\">.\n\[<a href="\/whois\/(.*?)">Whois<\/a>\]',
	},
	Bing =>{
		SITE	=>	"Bing.com",
		URL		=>	"http://api.search.live.net/xml.aspx?Appid=%s&query=ip:%s&Sources=Web&Version=2.0&Options=EnableHighlighting&Web.Count=50&Web.Options=DisableQueryAlterations&Web.Offset=",
		SP		=>	'BingApi()',
	},
	ewhois =>{
		SITE	=>	"Ewhois.com",
		URL		=>	"http://www.ewhois.com/",
		HEAVY	=>	1,
		SP		=>	'eWhois()',
	},
	Sameip =>{
		SITE	=>	"Sameip.org",
		URL		=>	"http://sameip.org/ip/%s/",
		REGEX	=>	'<a href="http:\/\/.*?" rel=\'nofollow\' title="visit .*?" target="_blank">(.*?)<\/a>',
	},
	Robtex =>{
		SITE	=>	"Robtex.com",
		URL		=>	"http://www.robtex.com/ajax/dns/%s.html",
		REGEX	=>	"<li><a href\=\"\/dns\/.*?\.html\#shared\" >(.*?)<\/a><\/li>",
	},
	Webmax =>{
		SITE	=>	"Tools.web-max.ca",
		URL		=>	"http://ip2web.web-max.ca/?byip=1&ip=%s",
		REGEX	=>	'<a href="http:\/\/.*?" target="_blank">(.*?)<\/a>',
	},
	DNStrails =>{
		SITE	=>	"DNStrails.com",
		URL		=>	"http://www.DNStrails.com/tools/lookup.htm?ip=%s&date=recent",
		REGEX	=>	'date=recent">(.*?)<\/a>\s\(as\sa\swebserver\)',
	},
	Viewdns =>{
		SITE	=>	"Viewdns.info",
		URL		=>	"http://viewdns.info/reverseip/?host=%s",
		SP		=>	"ViewDNS()"
	}
);

# Process options.
my ($target,$timeout,$threadz,$check,$print,$bing,$proxy,$proxy_auth,$useragent,$filename,$verbose);

if ( @ARGV > 0 )
{
	GetOptions( 't|target=s'	=> \$target,
				'timeout=i'		=> \$timeout,
				'threads=i' 	=> \$threadz,
				'c|check'		=> \$check,
				'print'			=> \$print,
				'list'	 		=> \&list_serv,
				'b|bing'		=> \$bing,
				'proxy=s'		=> \$proxy,
				'proxy-auth=s'	=> \$proxy_auth,
				'user-agent'	=> \$useragent,
				'o|output=s'	=> \$filename,
				'v|verbose' 	=> \$verbose,
				'h|help'		=> \&usage) or exit;
}
else
{
	print "[*] Usage    : perl $b [OPTIONS]\n";
	print "    EXEMPLE  : perl $b -t www.target.com -o result.txt\n\n";
	print "[*] Try 'perl $b -h' for more options.\n";
	exit;
}


if($^O =~ /MSWin32|cygwin/ and ($threadz>10))
{
	print "\n[-] Sorry, maximum number of used threads is 10 for Windows to avoid some possible connection and performance issues\n\n";
	exit;
}

if ($target =~ /\d+.\d+.\d+.\d+/)
{
	# nice do nothing
}
elsif ($target =~ /([a-z][a-z0-9\-]+(\.|\-*\.))+[a-z]{2,6}$/)
{
	my $IP = getIP($target);
	if ($IP)
	{
		$target = $IP;
	}
	else
	{
		die "\n[!!] Unable to Resolve Host $target ! \n";
	}
}
else
{
	die "[-] Invalid Hostname or Ip address .\n";
}

my $DNSx = gethostbyaddr(inet_aton($target),AF_INET);
# Check if the target uses CloudFlare service
my $IPx = unpack("N",inet_aton($target));
if(($IPx >= 3428708352 and $IPx <= 3428708607) or ($IPx >= 3428692224 and $IPx <= 3428692479) or ($IPx >= 3340468224 and $IPx <= 3340470271) or ($IPx >= 2918526976 and $IPx <= 2918531071) or ($IPx >= 1729546240 and $IPx <= 1729547263))
{
	print "[WARNING] The target uses CloudFlare's service!!\n\n";
	print "[!] do you wanna continue? [y/n]:";
	my $choice=<STDIN>;
	chop($choice);
	if($choice eq "n")
	{
		print "\n[*] shutting down!!\n\n";
		exit;
	}
	else
	{
		print  "[+] OK! as you like\n";
	}
}

# Global variables
$bingApiKey  = 'B2EF5E9434B8778E2B01E5D6CE71545CCEC97C86';#get your own code
$VERSION     = '1.5';
$TMPdir      = "tmp";
$useragent ||= 'Mozilla/5.0 (Windows; U; Windows NT 5.1; fr; rv:1.9.1) Gecko/20090624 Firefox/3.5'; 
$filename  ||= "$target.txt";
$timeout   ||= 30;
$SIG{INT}    = \&trapsig;

mkdir $TMPdir or die "[-] Cant create tmp directory!\n" if ! -d $TMPdir;

my $ua = LWP::UserAgent->new(agent => $useragent);
$ua->timeout($timeout);
$ua->max_redirect(0);
$ua->conn_cache(LWP::ConnCache->new());
$ua->default_header('Referer' => "http://www.fbi.gov");
$|++;
if ($proxy)
{
	$proxy .= ":8080" if not $proxy =~ /:/;
	# connect to the proxy
	my $req = HTTP::Request->new(CONNECT => 'http://'.$proxy.'/' );
	if (defined $proxy_auth)
	{
		my ($user,$password)=split(":",$proxy_auth);
		$req->proxy_authorization_basic($user, $password);
	}
	my $res = $ua->request($req);
	# connection failed
	if ( not $res->is_success ){
		print "\n[-] failed to connect to the proxy... ignore it\n\n";
	}
	else
	{
		$ua->proxy(http => "http://$proxy/");
	}
}

print "\n[*] Its take few second's to complete the operation....\n\n";
print "[+] Processing:\n";

### Functions

sub list_serv
{
	print "[*] List of available Reverse Ip Lookup services:\n\n";
	foreach $X (keys %SERV)
	{
		print "    -> $SERV{$X}->{SITE}\n";
	}
	print "\n";
	exit;
}

sub trapsig 
{
	print "\n\n[!!] Caught Interrupt (CTRL+C), Aborting\n";
	print "[!!] Saving results\n";
	save_report($filename);
	exit();
}
sub add
{
	my $x = lc($_[0]);
	($x =~ /[\<\"]|freecellphonetracer|reversephonedetective|americanhvacparts|freephonetracer|phone\.addresses|reversephone\.theyellowpages|\.in-addr\.arpa|^\d+(\.|-)\d+(\.|-)/) ? return:0;
	push(@{$SERV{$X}->{DUMP}},$x) if($verbose);
	$x =~ s/http(.|s)\:\/\/|\*\.|^www\.|\///;#remove shit
	++$SERV{$X}->{NB};
	push(@result,$x);
}
sub getIP
{
	my @ip = unpack('C4',(gethostbyname($_[0]))[4]) or return;
	return join('.',@ip);
}

sub getDNS
{
	return gethostbyaddr(inet_aton($_[0]),AF_INET);
}

sub Req
{
	my ($URL,$data)=@_;
	my $res;
	if(!$data)
	{
		$res = $ua->get($URL);
	}
	else
	{
		$res = $ua->post($URL, 
		{
			$data => $target,
		});
	}
	if(!$res->is_success)
	{
		print "[!] Error: ".$res->status_line."\n" if ($verbose);
	}
	return $res->content;
}

sub Yougetsignal
{
	my $resu = Req(sprintf($SERV{$X}->{URL},$target),$SERV{$X}->{DATA});
	while ($resu =~ m/\["(.*?)\"\, \"(1|)\"\]/g)
	{
		add($1);
	}
	if ($resu =~ m/Daily reverse IP check limit reached for/i)
	{
		$ERROR = "E1";
		$SERV{$X}->{NB} = $ERROR;
	}
}

sub eWhois
{
	sub callback 
	{
		while($_[0] =~ m/"(.*?)","","","(UA\-[0-9]+\-[0-9]+|)",""/g)
		{
			add($1);
		}
	}
	my $url = "http://www.ewhois.com/export/ip-address/$target/";
	my $cookie_jar = HTTP::Cookies->new(autosave => 1);
	my $browser = LWP::UserAgent->new(agent => $useragent);
	$browser->cookie_jar($cookie_jar);
	my $resu = $browser->post("http://www.ewhois.com/login/",
	{
		'data[User][email]'=>'r12xr00tu@gmail.com',
		'data[User][password]'=>'Rev:::Rev',
		'data[User][remember_me]'=>'0'
	});
	if(!$resu->header('Location'))
	{
		print "[-] Sorry, we cant login to eWhois!\n";
		return;
	}
	$browser->get($url, ':content_cb' => \&callback );
}

sub Whoiswebhosting
{
	for (my $i=1;$i<=100;$i++)
	{
		my $resu = Req(sprintf($SERV{$X}->{URL},$target,$i));
		if ($resu =~ m/<a href=\"\/.*?\?pi\=\d+\&ob\=SLD\&oo\=DESC\">Next\&nbsp\;\&gt\;\&gt\;<\/a>/g)
		{
			while ($resu =~ m/<td><a href="http:\/\/whois\.webhosting\.info\/.*?\.">(.*?)\.<\/a><\/td>/g)
			{
				add($1);
			}
		}
		else
		{
			while ($resu =~ m/<td><a href="http:\/\/whois\.webhosting\.info\/.*?\.">(.*?)\.<\/a><\/td>/g)
			{
				add($1);
			}
			if ($resu =~ m/The security key helps us prevent automated searches/i)
			{
				$ERROR = "E2";
				$SERV{$X}->{NB} = $ERROR;
				last;
			}
			last;
		}
	}
}

sub ViewDNS
{
	my $resu = Req(sprintf($SERV{$X}->{URL},$target));
	if($resu =~ m/<table border="1"><tr><td>Domain<\/td><td>Last Resolved Date<\/td><\/tr>(.*?)<\/table><br><\/td><\/tr>/i)
	{
		$resu = $1;
		while($resu =~ m/<tr><td>(.*?)<\/td><td align="center">/gi)
		{
			add($1);
		}
	}
}

sub BingApi
{
	my $b;
	my $off = 0;
	for(my $offset=50;$offset<=500;$offset+=50)
	{
		my $resu = Req(sprintf($SERV{$X}->{URL},$bingApiKey,$target).$offset);
		if ($resu =~ m/<web\:Offset>(.*?)<\/web\:Offset>/gi)
		{
			$off = $1;
		}
		if ($off == $offset)
		{
			while ($resu =~ m/<web\:Url>http:\/\/(.*?)<\/web\:Url>/g)
			{
				$b = $1;
				push(@bingtrash,$b) if $bing;
				$b =~ s/\/.*// if index($b,"/");
				add($b);
			}
		}
		else
		{
			last;
		}
	}
}

sub add2tmp
{
	syswrite(TMP,gethostbyaddr(inet_aton($_[0]),AF_INET).":$_[0];");
}


sub checkDomain
{
	if(getDNS('www.'.$_[0]) eq $DNSx)
	{
		$NEWNB++;
		print "    Found : $_[0]\n";
		push(@resx,'www.'.$_[0]);
	}
	elsif(getDNS($_[0]) eq $DNSx)
	{
		print "    Found : $_[0]\n";
		$NEWNB++;
		push(@resx,$_[0]);
	}
	else
	{
		print "    Try : $_[0]\n";
	}
}

sub save_report
{
	my $filen = $_[0];
	if($donecheck && $threadz && $thread_support)
	{
		open (IN,"./$TMPdir/Rev-tmp.txt") or print ("\n[!] Can't create the file ($filen)\n");
		open (OUT,">$target-checked.txt") or print ("\n[!] Can't create the file ($filen)\n");
		syswrite(OUT,"#Rev Output  $VERSION\n# Those are the domains hosted on the same web server as ($target).\n# Results were tested and checked, so all old records were removed.\n\n");
		while(<IN>)
		{
			chomp;
			if (index($_,$DNSx))
			{
				$NEWNB++;
				s/$DNSx://; 
				syswrite(OUT,"$_\n");
			}
		}
		close(IN);
		close(OUT);
	}
	elsif($donecheck && !$threadz)
	{
		open (OUT,">$target-checked.txt") or print ("\n[!] Can't create the file ($filen)\n");
		syswrite(OUT,"# Checked domains - Reverser$VERSION\n# Those are the domains hosted on the same web server as ($target).\n# Results were tested and checked, so all old records were removed.\n# Total domains: $NEWNB\n\n");
		foreach (@resx)
		{
			syswrite(OUT,"$_\n") if ($_);
		}
		close(OUT);
	}
	open (F,">$filen") or print ("\n[!] Can't create the file ($filen)\n");
	syswrite(F,"# Reverser By Alexcerus $VERSION\n# Those are the domains hosted on the same web server as ($target).\n# Total domains: $TOTALNB\n\n");
	foreach(@result)
	{
		syswrite(F,"$_\n") if ($_);
	}
	close(F);
}


#----------#
foreach $X (keys %SERV)
{
	my $match = $SERV{$X}->{REGEX};
	syswrite(STDOUT,"   -> $SERV{$X}->{SITE}\n");
	if(!$SERV{$X}->{SP})
	{
		$res=Req(sprintf($SERV{$X}->{URL},$target),$SERV{$X}->{DATA});
	}
	else
	{
		eval($SERV{$X}->{SP});
		next;
	}
	while($res =~ m/$match/g)
	{
		add($1);
	}
}

die "\n\n[-] Sorry, there is no data were retrieved!\n" if(scalar(@result)<1);

@result = sort(grep { ++$R12{$_} < 2 } @result);
undef(%R12);
$TOTALNB = scalar(@result);

if($verbose)
{
	print "\n[+] DEBUG:\n\n";
	foreach $X (keys %SERV)
	{
		syswrite(STDOUT,"  + $SERV{$X}->{SITE}\n");
		foreach $DMP (@{$SERV{$X}->{DUMP}})
		{
			syswrite(STDOUT,"    - $DMP\n");
		}
	}
}

if($bing)
{
	if (scalar(@bingtrash)>0)
	{
		syswrite(STDOUT,"[+] saving Bing shit...  ");
		my $file = "bingresults-$target.txt";
		open (BING,">$file") or print ("\n[!] Can't create bing shit\n");
		print BING "# Reverser By Alexcerus $VERSION\n# Those are all search results from Bing.com ($target).\n\n";
		foreach (@bingtrash)
		{
			print BING "$_\n";
		}
		close(BING);
		syswrite(STDOUT,"DONE\n");
		print "[+] bing results were saved into $file\n";
	}
	else
	{
		print "\n[-] no bing data!!\n\n"
	}
}

if ($check)
{
	my ($domain,$t);
	print "\n[x] Checking and removing old records from results\n";
	if ($threadz && $thread_support)
	{
		open(TMP,">./$TMPdir/log-tmp.txt");
		TMP->autoflush(1);
		foreach (@result)
		{
			threads->create(\&add2tmp,"www.$_")->detach;
			$t++;
			if($t==$threadz)
			{
				$s+=$t;
				print "\r passed $s";
				undef $t;
				sleep 1;
			}
		}
		close(TMP);
	}
	else
	{
		print "[-] Sorry your PERL installation doesn't support threads!\n\n" if !$thread_support;
		&checkDomain($_) foreach (@result);
	}
	$donecheck = 1;
	print "[+] Done\n";
}
&save_report($filename);


print "\n[x] Result of $target : \n\n";

print "                        +--------+\n                        |   NB   |\n+-----------------------+--------+\n";
foreach $X (keys %SERV)
{
	printf "| %-22s| %-7s|\n",$SERV{$X}->{SITE},(($SERV{$X}->{NB}) ? $SERV{$X}->{NB} : 0);
	print "+--------------------------------+\n";
}
printf "  %-14s| Total | %-7s|\n"," ",$TOTALNB;
print "                +----------------+\n";
print "[+] After removing old records : $NEWNB\n\n" if $donecheck;

if ($ERROR)
{
	print "+--Keys------------------------------------+\n";
	print "|E1: Daily reverse IP check limit reached. |\n";
	print "|E2: Some Security Measures (Captcha).     |\n";
	print "+------------------------------------------+\n";
}
if ($TOTALNB != 0 and $print)
{
	print "[+] Results:\n";
	my $v = 0;
	foreach my $RD (@result)
	{
		$v++;
		print "  $RD\n";
		if($v==20){<STDIN>;undef $v};
	}
}
print "[+] All results saved here => ($filename)\n";
print "[+] All checked domains are saved to ($target-checked.txt)\n" if ($NEWNB>0);