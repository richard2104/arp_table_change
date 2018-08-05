# arp_table_change
상대방의 ip를 입력받아 Gateway ARP 위조 신호를 만들어 table 변조시킴


> Attacker(자신)가 Victim에서 거짓된 ARP Reply packet을 날려 Victim의 ARP Table을 변조할 수 있는 프로그램을 작성하라.

1. Victim의 IP는 인자로 입력받는다.

2. Attacker는 자신의 특정 network interface에 대해서 ip, mac, gateway 정보를 얻어 온다.

3. Attacker는 Victim과 Gateway에 대한 mac을 ARP Request를 이용하여 알아 낸다.

4. Attacker는 1~3 과정에서 얻은 정보를 이용하여 거짓된 ARP Replay packet을 Victim에게 날린다.

5. Victim에서 ARP Table이 제대로 변조되어 있는지 확인한다.
