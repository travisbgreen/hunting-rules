# hunting-rules
Suricata 4.1+ rules for network anomaly detection

FP / suggestions to @travisbgreen or travis|40|travisgreen.net




# notes

## ideas for rules
- any serialized php
- serialized otherstuff? ysoserial?
- any netbios
- tos: pretty much anything wierd here

``` bash
# test with
$ time sudo /opt/suricata-4.1.0-rc2/src/suricata -c /opt/suricata-4.1.0-rc2/suricata.yaml -l . -S ~/rules/hunting/hunting.rules -k none -r ./merged.pcap && cat fast.log

# fix sids
python ~/scripts/sidfix.py ./hunting.rules > ./hunting.rules.2
mv hunting.rules.2 hunting.rules

# generate from python
foo = foo.split('\n')[:-1]
for f in foo: 
  print 'alert dns any any -> any any (msg:"HUNT Abused TLD .%s in DNS"; flow:established; dns_query; content:".%s"; endswith; threshold: type limit, track by_src, seconds 60, count 1; classtype:bad-unknown; sid:2600134; rev:1;)' % (f,f)
for f in foo:
  print 'alert tls any any -> any any (msg:"HUNT Abused TLD .%s in SNI"; flow:established,to_server; tls_sni; content:".%s"; endswith; classtype:bad-unknown; sid:2600134;)' % (f,f)

foo = '''
men
tk
ml
ga
cf
gq
work
date
top
review
stream
trade
loan
science
gdn
click
date
racing
'''

```
