Do wykorzystania reguł niezbędny jest podany niżej config z działającą usługą auditd na dowolnej dystrybucji Linuxa (Redhat ma problemy z resetowaniem usługi auditd ze względów bezpieczeństwa).

Żeby zamienić config trzeba:
-wyłączyć serwis auditd
-usunąć plik audit.rules w /etc/audit/rules.d
-pobrać i wrzucić nowy plik audit.rules do folderu rules.d (alternatywnie można wget z tego linku "https://raw.githubusercontent.com/Neo23x0/auditd/master/audit.rules")
-zrestartować serwis
