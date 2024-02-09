# Blockchain Based Casino
# Background
You plan to set up a blockchain-based casino in the fictional country of Schweizerland. This casino supports only one type of bet: the bettor puts down a deposit of 1 Schweizerlandish schilling, which is conveniently equal to 0.01 ETH. With probability 0.5, the bet is won and you have to pay them 2 schillings. Similarly, with probability 0.5, the bet is lost and you get to keep their schilling.

The Schweizerlandish authorities are quite strict and they want to make sure that you cannot fraudulently control the result of the bets. So, they require you to prove to them that the bets are actually fair. However, they are also pretty open-minded (or at least they claim to be) and are willing to help you in the generation of the required random numbers. Specifically, they have heard that you have a protocol in mind in which a random number can be generated by the participation of any number 𝑛 of players. The authorities require you to ensure that they always control at least 𝑡 = ⌈ 𝑛 + 1⌉ of the players, so that the public can trust your casino. They also require your protocol to be open to the public, so that anyone can sign up and contribute to the random number generation if they wish to do so. Unfortunately, although the public trusts the authorities, you as the casino owner cannot trust them. You worry that they might use their huge influence in the RNG process to tamper with the results and help their friends win a lot of bets in your casino. Finally, although you are aware of the standard methods of random number generation on the blockchain, none of them really appeal to you. They are all slow and take a long time to generate even one random number. Your bettors like to see the results of their bets immediately. You cannot ask a bettor to wait for a VDF to be computed, or for many RNG participants to reveal their choices or perform secret reconstruction. They expect almost-instant results, i.e. within a few blocks.

So, you go to the authorities and propose the following scheme:
1. At the beginning of the day,we use a specialized RNG protocol with the above properties required by the authorities, to generate a random number 𝑟. However, we ensure that 𝑟 is only visible to the casino and no one else has any information about it.
2. We fix a deterministic pseudo-random number generator function, e.g. the rand() function in a standard implementation of C, which can have any seed.
3. The casino deposits a huge amount of money in the smart contract.
4. Each bettor deposits 1 schilling for each bet and also provides a random number 𝑘 of their
choosing. These are recorded in the smart contract. In response, the casino uses 𝑘 + 𝑟 as the seed andcomputesarandomnumber,i.e.itperformssrand(𝑘+𝑟); 𝑥=rand();Thecasinodiscloses neither 𝑟 nor 𝑥. It only tells the smart contract whether 𝑥 is even or odd. This announcement is recorded in the contract. If 𝑥 is even, the bettor has won. Otherwise, they have lost. The contract pays the bettor accordingly.
5. At the end of the day, the casino announces the value of 𝑟 that was used during the day. The authorities and every bettor can verify that (i) 𝑟 was really generated by the RNG process of Step 1 and was therefore not under the casino’s control, and (ii) the casino did not cheat in any of the bets.
6. If any cheating is detected, it can be reported to the smart contract, which would use the casino’s deposit to pay twice as much as their losses to the wronged bettors.
7. If no cheating is reported to the smart contract after a fixed deadline, or if all the reports were false, the casino can get its money back.
Your proposal is acceptable to the authorities, but they want to see more details.

Your Project
Design a protocol that solves the problem above and satisfies the following additional requirements. Submit your protocol as a single file named protocol.pdf, explaining its steps, the requirements it satisfies (1–7, a–j), and arguments for why it satisfies the claimed requirements. Then, implement it in Solidity and submit the code as a single file named contract.sol. If you cannot satisfy all the requirements, try to achieve as many of them as possible. Similarly, if you cannot implement all parts, make as much progress as possible and explain your progress in your pdf file. For simplicity, you can have any implementation of srand and rand that you like in your code. We will not care if these are not really pseudo-random number generators.
The additional requirements:

a. The RNG process at Step 1 above should be open to everyone for participation as players, but you have to automatically give control of at least 𝑡 of the players to the authorities. You can assume that the authorities have provided you with their public key (address).

b. The result 𝑟 of the RNG process at Step 1 above should only be visible to you (the casino). Ideally, it should be encrypted using your public key, so that no one else can decrypt it.
Hint: Look into non-RSA encryption schemes and a concept called “homomorphic encryption”.

c. The RNG at Step 1 should be tamper-proof. Specifically:
  • The casino should not be able to tamper with the result even if it colludes with all the players who are not controlled by the authorities.
  • The authorities should not be able to tamper with the result even if they collude with all the players who are not controlled by the casino. You can assume that at least one RNG player is
    controlled by the casino.
  • No one else should be able to tamper with the result, including blockchain miners.

d. The RNG at Step 1 should be unpredictable. No one, including the casino and the authorities, should be able to guess 𝑟 or obtain any information about it before it is delivered in an encrypted format to the casino. Similarly, at any time strictly before the casino’s announcement at Step 5, no one other than the casino should be able to find any information about 𝑟. This must hold even if the authorities collude with all non-casino players to predict 𝑟. We assume the casino would not leak 𝑟 before Step 5 since it would cause them to lose all the bets.

e. The value 𝑟 should be generated uniformly at random. You can assume that 𝑟 is supposed be a 16-bit integer. Thus, each value between 0 and 2^16 − 1 should have the same probability 2^−16 of being the chosen 𝑟. If you wish, you can also use larger bounds for 𝑟.

f. The RNG of Step 1 should not ever fail. You can assume that the players controlled by the authorities will perform all steps of the RNG to completion and that they will not cheat in any detectable way. However, if your protocol allows the authorities to cheat and not be detected, they might choose to do so. On the other hand, you cannot assume anything about the other RNG players.

g. All players in the RNG should receive incentive payments that ensures they are incentivized to honestly follow the protocol until its completion. These payments should come from the casino’s deposit.

h. In Step 5, the casino should be able to reveal the value of 𝑟 and prove to everyone that the revealed value is the same 𝑟 that was generated in Step 1. Any cheating by the casino should also be detectable. Such cheating should be provable to the contract so that it can penalize the casino.

i. The deposit put by the casino should be large enough to ensure the bettors can be compensated twice the money they lost in case the casino cheats.

# Graded by: Professor Amir Goharshady
Comments: Compiled with no warnings. This was one of the best solutions to this final project. Nice job! 
