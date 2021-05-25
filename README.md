# AlgebraScan
Second project of advanced scripting in Algebra University


Usage: 
```py 
    sudo python Main.py <ip> <modes> <args>
```


Mode:
<ul>
    <li>“-a”or “--arp” –script needs to make ARP scan of local network.</li>
    <li>“-i” or “--icmp” –script needs to make ICMP scan of local network.</li>
    <li>“-t” or “--tcp” –script needs to make TCP scan of local network.</li>
    <li>“-u” or “--udp” –script needs to make UDP scan of local network</li>
</ul>

Args For udp or tcp:

<ul>
    <li>“-p x”–script needs to check port x.</li>
    <li>“-p x,y”–script needs to check port x and y.•“-px,y,...”–script needs to check all ports separated with comas.</li>
    <li>“-p x-y”–script needs to check all ports between x and y.</li>
    <li>“-p x-y,z” –script needs to support mixing ranges and exact ports.</li>
</ul>