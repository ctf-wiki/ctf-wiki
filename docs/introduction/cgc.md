[EN](./cgc.md) | [ZH](./cgc-zh.md)
&gt; This section is taken from Professor Li Kang&#39;s speech at the ISC Internet Security Conference on August 17, 2016, &quot;Understanding and Exploiting Vulnerabilities in the Network Super Challenge.&quot;


The CGC Network Super Challenge is the world&#39;s first machine network attack and defense competition. The game is fully automated without any manual intervention. Test machine automatic vulnerability mining, automatic software hardening, automatic leak utilization and automatic network protection level. Use a simplified Linux operating system ------DECREE, similar to Snort
The rules filter the firewall. Vulnerability mining for Linux binaries. All teams have no source code.


In the 2016 CGC competition, the challenged title included 53 CWEs. It contains 28 heap overflow vulnerabilities, 24 stack overflow vulnerabilities, 16 null pointer access vulnerabilities, 13 integer overflow vulnerabilities, and 8 UAF vulnerabilities.


The offense and defense process is challenged by the organizer, and each team server can provide patches, firewall rules and attack programs to the organizers. Patched programs and firewall rules are distributed to other teams. The organization runs a challenge program for each team, conducts service testing and attacks, and evaluates them.


## Performance Evaluation Indicators


1. The response time of normal service access;
2. Patch frequency;
3. The efficiency of the reinforcement procedure;
4. Statistics on the number of successful defense attacks;
5. Statistics on the number of successful attacks.


## Clear core tasks


Get the binary program, perform automatic analysis, and reinforce the program and generate the attack program after clearing the firewall rules.


## Analytical method


1. Specific implementation - use the normal execution mode;
2. Symbol execution - path selection for the auxiliary Fuzzing phase;
3. Mixed Execution - Symbol execution with specific inputs, selecting the path based on the input, but retaining the symbol condition.


## CGC Experience Summary


1. The difficulty of perfect defense is much greater than the difficulty of generating an attack;
2. Binary hardening procedures need to avoid loss of functionality and minimize performance loss;
3. The trend of safe automated processing has taken shape, and most teams can attack simple applications and generate effective defense in a matter of seconds;
4. The strategy research in confrontation is worth looking forward to, based on the offensive and defensive capabilities of the opponent and the opponent, make reasonable adjustments to resources and actions.