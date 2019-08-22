[EN](./experience.md) | [ZH](./experience-zh.md)
First of all, the normal game will provide the interface to submit the flag, the interface address is similar to `http://172.16.4.1/Common/submitAnswer`. In general, we need to submit the flag through the interface according to the documentation requirements given by the organizer. Require interface address to use Post in the game
The method is submitted with two parameters, one is `Answer`, the value is the obtained flag string, and the other is `token`, which is the team token of each team.


Then the organizer will also provide each participating team with a virtual machine for analyzing network traffic**, and the player needs to access the address to download the traffic file for analysis.


## Follow the Gamebox status


You can check the status of your own and enemy GameBox during the game. Always pay attention to get the game information as soon as possible, and make adjustments based on the information.


For the own GameBox, there is a reason why the GameBox is down:


1. The organizer&#39;s referee system has made a mistake and misidentified GameBox as unavailable. This situation can usually be found before the start of the game. If this is the case, it should be reported to the staff as soon as possible to reduce the loss.
2. The program patch error caused the service to be unavailable. After the program is finished, you need to enter the next round of attention to the GameBox state. If the patch error is not available, you need to save it in time. But don&#39;t worry too much about replacing the original unpatched vulnerability program. Because down
Off is a small score for all teams, and the direct vulnerability program will make a strong team directly to get a high score. Therefore, it should be treated according to specific circumstances.
3. The opponent&#39;s improper attack caused the GameBox to be unavailable. If found, it needs to be remedied in time.
4. The organizer strengthens the program check. In this case, the organizer will announce the notice to all the players. The status on the GameBox status wall shows that the team&#39;s GameBox large area is not available.


For the enemy GameBox. We can get the following information.


1. Observe which teams&#39; GameBoxes are not defensively successful based on the attack flow. More attacks can be achieved for these teams
2. When a team takes out a blood. It can be inferred from the status of each team GameBox whether a blood team has written a usage script. After writing the script, you can observe whether your own defense is done.


## Clearing sections and ports


During the competition, the organizer will arrange a reasonable network segment distribution.


During maintenance, you need to connect to the network segment where the GameBox is located, and log in according to the CTF account and password provided by the organizer. When interacting with other teams&#39; GameBox, you need to connect to the corresponding network segment to interact with the vulnerability program. Submitting the flag will need to be submitted to the specified answering platform.


!!! warning

Of particular note here is the port. If the port is not easily mistaken, such an error is difficult to detect, and such mistakes can also cause unnecessary losses. There may even be a fatal situation where the flag cannot be submitted for a long time. So you need to be careful.


## Service patch and defense


1. The program patch should be reasonable and meet the referee system check conditions. Although the system check is not public, it is generally not too difficult.
2. Program patch is modified using IDA. IDA provides three ways.
Patch: byte, word, assemble. The bytecode modification is easier to use. Because the byte-by-byte modification does not need to consider the assembly instructions, generally such modification changes are also very small, and are very easy to use in certain occasions. Although the modification of the assembly instruction level does not require modification of the bytecode, it also causes some inconvenience. For example, it is necessary to additionally consider the length of the assembly instruction, whether the structure is reasonable and complete, whether the logic is the same as the original, whether the modified assembly instruction is legal or not.
3. Remember to back up the original vulnerability program for patch analysis when using the patch program. When uploading a patch, you should delete the original vulnerability program, and then copy the patched program into it. After copying it, you need to give the program the appropriate permissions.
4. In the general game, the vulnerability program will have more than a dozen places to patch. Patches must not only be effective and reasonable, but also satisfy the analysis that can prevent or confuse opponents to a certain extent.


## Constructing a Script Framework to Quickly Launch an Attack


In the course of the offensive and defensive competition, a blood is particularly important. So having an attack script framework is very beneficial. Quickly develop attack scripts, you can maintain a dominant position in the early stage, and you can save time and take time to defend.


## Some strategies of the game


1. In the course of the game, it is not advisable to die on a single question. Due to the superiority of a blood, it is necessary to fully understand the difficulty of the game during the competition. First, analyze the ** simple question **, step by step.
2. During the competition, the two poles will be seriously differentiated. Efforts should be made to strike teams that are comparable to their own strengths and stronger than their own teams, especially if the scores are almost the same, and they must be strictly guarded against them.
3. NPC will send attack traffic from time to time during the game. The payload can be obtained from the attack traffic.
4. Be sure to fight the NPC to death.
5. At the beginning of the game, all the management passwords can be set to the same password, which is convenient for the player to log in and manage. Back up all the files in the initial stage for sharing within the team.