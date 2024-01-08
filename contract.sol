// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.2 <0.9.0;

// Contract is used once as clearing all mapping values involve lots of gas
// To start another betting game, the casino needs to deploy the contract again
contract protocol
{
    //List of stored addrsses
    address payable casinoAddress;
    address payable authority = payable(0x5B38Da6a701c568545dCfcB03FcB875f56beddC4);

    // Flags
    bool announcedPK;
    bool deposited;
    bool bettingPeriodStarted;
    bool committedRandParameters;
    bool revealedRandParameters;
    bool casinoCheated;
    bool secretKeyRevealed;
    bool revealedRandomNumber;
    bool verifiedRNG;

    // Encryption Parameters: public keys (x, N)
    uint pk_x;
    uint pk_N;

    // committed LCG parameters for implementation of rand()
    bytes32 hash_rand_a;
    bytes32 hash_rand_b;
    bytes32 hash_rand_n;

    // Revealed LCG Parameters
    uint rand_a;
    uint rand_b;
    uint rand_n;

    // Encrypted random number r used for seed
    // Stored as an array of 16 unsigned integers, each representing bits 0 or 1
    uint[16] encrypted_r;

    // Hash of each player's random number Rn
    // Stored as an array of 16 hashes, each representing hash of encRn (input parameter of contributeRn)
    mapping(address => bytes32[16]) hashEncRn;
    mapping(address => bool) contributedRn;

    //Decryption keys (Only revealed if not all player has revealed Rn after betting period has ended)
    uint sk_p;
    uint sk_q;

    // revealed random number r by casino
    uint revealed_r;

    // Constructed from either Rn or decryption keys depending on whether all players have revealed Rn
    uint decrypted_r;


    // mappings to keep track of the states of k
    mapping(uint => address) owner_k; // Indicates bettor of k
    mapping(uint => bool) returned_result_k; // Indicateds whether casino has revealed result of bet on k
    mapping(uint => bool) result_k; // result of bet on k (true = win and false = loss)
    mapping(uint => bool) withdrawn_winning_k; //indicates whether bettor has withdrawn winnings of k or refund on bet cancellation
    mapping(uint => uint) bet_period_k; // Keeps track of the time bet was made. If casino does not return result within few blocks, bettor has the right to cancel bet
    mapping(uint => bool) cheatRefunded; // If casino has cheated, bettor can receive twice the amount of bet.
    mapping(uint => bool) cancelledBet;

    // Indicates whether player has withdrawn commision
    mapping(address => bool) withdrawn_commission;

    // holds balance of bettors and players for pull over push mechanism
    mapping(address => uint) balance;

    // Global variables
    uint maxBets;
    uint numBets;
    uint numPublicPlayers;
    uint numAuthorities;
    uint numRevealedPublic;
    uint numRevealedAuthority;

    // Periods
    uint init_Period; // Announce public keys (x, N)
    uint contributeRN_Period; // Public players contribute Rn
    uint authorityRN_Period; // Authorities contribute Rn
    uint deposit_Period; // Betting commnces
    uint endBettingPeriod; // Betting ends
    uint reveal_r_period; // Casino announces r
    uint reveal_Rn_period; // Each player reveals Rn
    uint reveal_sk_period; // Reveal secret key if not all players have revealed
    uint verification_period; // RNG verification using revealed Rn if each player reveals. Otherwise casino must reveal SK.

    event logMessage(string msg);

    //Helper function - Modular Exponentiation
    function powmod(uint base, uint exponent, uint modulus) private pure returns(uint){
        uint result = 1;
        base = base % modulus;
        if(base == 0)
            return 0;
        while (exponent > 0) {
            if (exponent % 2 == 1)
                result = (result * base) % modulus;
            exponent = exponent >> 1;
            base = (base * base) % modulus;
        }
        return result;
    }

    //Helper Function - computes GCD of two numbers
    function gcd(uint a, uint b) private view returns(uint) {
        if (a == 0)
            return b;
        return gcd(b % a, a);
    }

    constructor()
    {
        //Set Casino's address
        casinoAddress = payable(msg.sender);

        //Initially, all elements of encrypted_r is 1, which is equivalent to randrom number r being 0
        for(uint i = 0; i< 16; i++) {
            encrypted_r[i] = 1;
        }

        //Set all periods that will take place
        init_Period = block.number + 50;
        contributeRN_Period = init_Period + 150;
        authorityRN_Period = contributeRN_Period + 150;
        deposit_Period = authorityRN_Period + 50;
        endBettingPeriod = deposit_Period + 6000;
        reveal_r_period = endBettingPeriod + 50;
        reveal_Rn_period = reveal_r_period + 150;
        reveal_sk_period = reveal_Rn_period + 50;
        verification_period = reveal_sk_period + 1000;
    }

    // PHASE 1: Casino announces public key (x, N)

    // Casino announces GM public key (x, N) used for encryption of random number (Rn)
    // Unless (x, N) is announced, player cannot particpate in RNG and bettors cannot make bets
    function announcePK(uint x, uint N) public
    {
        require(block.number <= init_Period);
        require(msg.sender == casinoAddress); // Access Control
        require(!announcedPK, "Public Key announced!"); //Prevents modification once announced
        announcedPK = true;

        pk_x = x;
        pk_N = N;
    }

    // Getter function
    // Players get public keys from contract to encrypt Rn
    function getCasinoPK() public view returns(uint, uint)
    {
        require(announcedPK, "Public key not announced!");
        return (pk_x, pk_N);
    }

    // PHASE 2: Random Number Generation

    // Computed Off-Chain by player
    // Function encrypts Rn to format acceptable by contributeRn
    // Rn is random number chosen radomly from a unform distribution between 0 and 2^16-1
    // Y is an array of random numbers coprime to pk_N (set by the Casino during PHASE 1)
    function computeEncRn(uint16 Rn, uint[16] memory Y) private view returns(uint[16] memory)
    {
        //Ensures GCD of every element in Y and N are equal 1
        for(uint i = 0; i< 16; i++)
            require(gcd(Y[i], pk_N) == 1, "All elements in Y must be relatively prime to N");

        uint[16] memory ciphertext;
        for(uint16 i=0;i<16;++i)
        {
            if(Rn%2==1)
                ciphertext[i] = ((Y[i]**2 % pk_N) * pk_x) % pk_N;
            else
                ciphertext[i] = Y[i]**2 % pk_N;
            Rn/=2;
        }
        return ciphertext;
    }

    // Each public player contributes a random number chosen from a uniform distribution between 0 and 2^16-1
    function contributeRn(uint[16] memory encRn) public payable
    {
        require(block.number > init_Period && block.number <= contributeRN_Period);
        require(announcedPK, "Public key not announced");
        
        // Must make deposit in case player does not reveal number/ reveals incorrect Rn 
        // Disincentiveize players from placing garbage values in encRn and force them to properly encrypt Rn
        // We add back balance + commission once they revealed Rn
        require(msg.value == 0.1 ether);
        require(!contributedRn[msg.sender]); // Each player can only contribute Rn once
        contributedRn[msg.sender] = true;


        for(uint i = 0; i < 16; i++) 
        {
            // Encrypted number must fall between 0 and N. 
            // Prevents attack if player submits 0 for each element in encRn, causing every element in encrypted_r to be 0.
            require(encRn[i] > 0 && encRn[i] < pk_N, "Invalid Encryption");

            // Homomorphic encryption: Enc(R1) * Enc(R2) = Enc(R1 XOR R2). 
            // Multiply each element in both arrays
            encrypted_r[i] = (encrypted_r[i] * encRn[i]) % pk_N;

            // Keeps track of player's address and corresponding hash from each encRn[i]
            // Forces player to reveal Rn that corresponds to hash after betting period has ended
            // Thus, player cannot submit arbitrary/ garbarge encRn (encRn must be properly encrypted from Rn) if they want to receive commission
            hashEncRn[msg.sender][i] = keccak256(abi.encodePacked(encRn[i]));
        }
        numPublicPlayers +=1;
    }


    // Authorities contribute t numbers chosen randomly from a uniform distribution  between 0 and 2^16-1
    // AUthoritities must call this function greater than numPublicPlayers to control t players
    function authorityRn(uint[16] memory encRn) public payable returns(bytes32[16] memory)
    {
        require(block.number > contributeRN_Period && block.number <= authorityRN_Period);
        require(announcedPK, "Public key not announced");

        require(msg.value == 0.1 ether); 
        require(msg.sender == authority); // Access Control

        bytes32[16] memory prevHashEncRn;
        for(uint i = 0; i < 16; i++) 
        {
            // require(encRn[i] > 0 && encRn[i] < pk_N, "Invalid Encryption");
            encrypted_r[i] = (encrypted_r[i] * encRn[i]) % pk_N;

            // Since authorities submit t numbers, we are going to hash encRn[i] with the previous hash (refer diagram in documentation)
            // This forms hash chain which keeps integrity of Rn
            // Forces authorities to reveal all Rn that corresponds to hash after betting period has ended 
            // Ensures encRn is not arbitrary/ garbarge (Rn must be properly encrypted) if they want to receive commission
            prevHashEncRn[i] = hashEncRn[msg.sender][i]; 
            hashEncRn[msg.sender][i] = keccak256(abi.encodePacked(encRn[i], hashEncRn[msg.sender][i]));
        }
        numAuthorities +=1;

        // Hash will be used during reveal of Rn
        // Similar to reveal scheme for withdrawing deposit from two banks (China & Shanghai) example given during lecture.
        return prevHashEncRn;
    }
    
    //PHASE 3: casino fixes rand() and Make deposit

    // Done off-chain by casino
    // Return values are committed in function commitRandParameters
    function hashRandParameters( uint a, uint a_nonce, uint b, uint b_nonce, uint n, uint n_nonce ) private pure returns (bytes32, bytes32, bytes32)
    {
        bytes32 ha = keccak256(abi.encodePacked(a, a_nonce));
        bytes32 hb = keccak256(abi.encodePacked(b, b_nonce));
        bytes32 hc = keccak256(abi.encodePacked(n, n_nonce));
        return(ha, hb, hc);
    }

    // commitment of rand() parameters used in Linear Congruential Generator
    // Purpose is to fix implementation of rand()
    function commitRandParameters(bytes32 ha, bytes32 hb, bytes32 hn) public
    {
        require(block.number > authorityRN_Period && block.number <= deposit_Period);

        require(announcedPK);
        require(numAuthorities > numPublicPlayers, "Authorities must control more than half players"); 
        require(msg.sender == casinoAddress); //Access Control
        require(!committedRandParameters, "hash of rand() parameters committed"); //Prevents modification once committed
        committedRandParameters =true;

        hash_rand_a = ha;
        hash_rand_b = hb;
        hash_rand_n = hn;
    }

    // getter function - returns encrypted_r to casino
    function getEncrypted_r() public view returns(uint[16] memory) {
        require(msg.sender == casinoAddress);
        require(block.number > authorityRN_Period);
        require(committedRandParameters);
        return(encrypted_r);
    }

    // Provide funds for bettors who win and gurantees that casino does not cheat. If casino cheats, bettors paid back twice bet paid.
    // Once casino has deposited, it has approved that it accepts bets, thereofre bettingPeriod can start
    // Therefore casino must call this function to allow bets.
    function casinoDeposit() public payable
    {
        require(block.number > authorityRN_Period && block.number <= deposit_Period);

        require(announcedPK);
        require(committedRandParameters, "hash of rand() parameters have not been committed");
        require(numAuthorities > numPublicPlayers, "Authorities must control more than half players");
        require(msg.sender == casinoAddress); //Access Control
        require(!bettingPeriodStarted, "Betting Period has started"); //Once started, cannot be undone which makes this function callable once during the lifetime of the contract
        bettingPeriodStarted = true;

        // With the assumption 1 Schilling incentivizes players to follow the whole protocol
        // Computes maximum number of bettors in case cheating is detected and casino must refund all bets twice the amount of bet paid
        uint playerCommision = (numAuthorities + numPublicPlayers) * 0.01 ether;
        require(msg.value > playerCommision);
        maxBets = (msg.value-playerCommision) / (0.01 ether);
    }

    // Refunds back their players' deposits if period > deposit Period but casino has not started betting period
    function refundPlayer() public {
        require(block.number > deposit_Period && !bettingPeriodStarted);
        require(contributedRn[msg.sender]);
        contributedRn[msg.sender] = false;
        balance[msg.sender] += 0.1 ether;
    }

    function refundAuthority() public {
        require(block.number > deposit_Period && !bettingPeriodStarted);
        require(msg.sender == authority); //Acces control
        require(numAuthorities > 0);
        uint temp = numAuthorities;
        numAuthorities = 0;
        balance[authority] += temp * 0.1 ether;
    }

    // PHASE 4: Betting Period

    // Bettors can bet on a particular value of k, used to determine result of random number
    // Value of k must be unique since rand() is pseudorandom
    function bet(uint k) public payable
    {
        // Allow casino to compute k within last 10 blocks
        require(block.number > deposit_Period && block.number <= (endBettingPeriod-10));

        require(bettingPeriodStarted); // Approve that betting is allowed
        require(numBets <= maxBets, "Maximum number of bets reached"); // Insures bet can be refunded twice the lost bet in case casino cheats
        require(msg.value == 0.01 ether); // Bet value
        require(owner_k[k] == address(0), "Use a different k"); // unique k must be used for each submission since rand() is pseudorandom
        numBets += 1;
        
        bet_period_k[k] = block.number; //record transaction block number in case casino does not reveal bet result within 10 blocks
        owner_k[k] = msg.sender; //record owner of "unique" k
    }

    // Casino must announce bet result to smart contract
    // This announcement is recorded in contract and not modifiable to prevent casino from cheating
    function announceBetResult(uint k, bool kResult) public
    {
        require(block.number >= deposit_Period && block.number <= endBettingPeriod);

        require(bettingPeriodStarted);
        require(msg.sender == casinoAddress); // Access Control
        require(!returned_result_k[k], "Result on k has been returned"); //prevents modification to returned bet result
        require(owner_k[k] != address(0)); //Ensures that k has an owner
        returned_result_k[k] = true;

        result_k[k] = kResult;
    }

    // Bettors can check the bet result once casino has made an announcement
    function betResult(uint k) public
    {
        require(block.number > deposit_Period); // can check bet result up until casino sweeps his deposit

        require(bettingPeriodStarted);
        require(msg.sender == owner_k[k]); //Access Control
        require(returned_result_k[k], "Result has not been announced by Casino"); //Ensure result announced by casino

        // Prevents reentrancy or multiple calls, stealing funds from contract 
        // Also ensures bettor cannot call both cancelBet and betResult
        require(!withdrawn_winning_k[k], "You have checked the result of k"); 
        withdrawn_winning_k[k] = true;

        if(result_k[k]) {
            balance[owner_k[k]] += 0.02 ether;
            emit logMessage("Congratulations, you won!");
        }
        else {
            emit logMessage("Sorry, you lost.");
        }
    }

    // Smart Contract also provides the option of cancelling bet in case casino has not announced result after 10 blocks.
    function cancelBet(uint k) public{
        require(block.number > bet_period_k[k] + 10); // Allow bet cancellation if bet result not announced within 10 blocks

        require(msg.sender == owner_k[k]); //Access Control. Only bettors can cancel bets.
        require(!returned_result_k[k], "Bet result on k has been announced by Casino"); // Disallow bet cancellation when result has been announced by casino
        require(!cancelledBet[k]); //Players who cancelled their bets cannot get refunds on their bets if casino has cheated
        require(!withdrawn_winning_k[k], "You have withdrawn your money from k"); // Prevents reentrancy or multiple calls, stealing funds from contract and ensures bettor cannot call both cancelBet and betResult
        cancelledBet[k] = true;
        withdrawn_winning_k[k] = true;

        // Prevents casino from revealing lost bets only/intentionally not revealing win bets
        balance[msg.sender] += 0.02 ether;
    }

    //PHASE 5: Announcement of random numbers and rand() parameters

    // r must be announced within reveal_r_period, 
    // Otherwise RNG is considered unfair and each bettor receives twice as much as their losses
    function revealRandomNumber(uint r) public{
        require(block.number > endBettingPeriod && block.number < reveal_r_period);
        
        require(msg.sender == casinoAddress); // Access Control
        require(!revealedRandomNumber); //Prevents modification of random number r once it is announced
        revealedRandomNumber = true;

        revealed_r = r;
    }

    // Revealed rand_a, rand_b and rand_n which must match initial committment
    // Similarly, If rand() parameters are not announced by reveal_r_period, RNG is considered unfair
    function revealRandParameters(uint a, uint a_nonce, uint b, uint b_nonce, uint n, uint n_nonce) public
    {
        require(block.number > endBettingPeriod && block.number < reveal_r_period);

        // rand() parameters will never be announced if these two conditions are not satisied
        // casino considered to have cheated
        require(gcd(rand_a, rand_n) == 1, "GCD of a and n not equal to 1"); 
        require(rand_a > 1 && rand_n > 1); // Threshold to be set by an agreement between authority and casino

        require(msg.sender == casinoAddress); // Access Control
        require(!revealedRandParameters); 
        revealedRandParameters = true;

        require(keccak256(abi.encodePacked(a, a_nonce)) == hash_rand_a, "Hash does not match!");
        require(keccak256(abi.encodePacked(b, b_nonce)) == hash_rand_b, "Hash does not match!");
        require(keccak256(abi.encodePacked(n, n_nonce)) == hash_rand_n, "Hash does not match!");

        rand_a = a;
        rand_b = b;
        rand_n = n;
    }

    // PHASE 6: Public players and authorities reveal Rn to construct r

    // Helper Function - Checks validity of Rn submitted by public player
    function checkEncRn(uint16 Rn, uint[16] memory Y) private view returns(bool)
    {
        //Ensures GCD of every element in Y and N are equal 1
        for(uint i = 0; i< 16; i++)
            require(gcd(Y[i], pk_N) == 1, "Every element in Y must");

        uint encRn;
        for(uint16 i=0;i<16;++i)
        {
            if(Rn % 2 == 1)
                encRn = ((Y[i]**2 % pk_N) * pk_x) % pk_N;
            else
                encRn = Y[i]**2 % pk_N;
            Rn/=2;

            // Checks whether Rn is valid by comparing with stored hash of encRN
            require(hashEncRn[msg.sender][i] == keccak256(abi.encodePacked(encRn)), "Hash does not match!"); 
        }
        return true;
    }
    // The function publicRevealHash verifies whether encRn submitted during contributeRn function call is valid
    // Casino must announce r before each player can announce Rn
    // However, if casino fails to reveal by reveal_r_period, public players can still receive commision
    function publicRevealHash(uint16 Rn, uint[16] memory Y) public{
        require(block.number > reveal_r_period && block.number <= reveal_Rn_period);
        
        require(checkEncRn(Rn, Y)); // Indicates Rn is encrypted properly and can be used to compute stored hash
        require(!withdrawn_commission[msg.sender], "Commision has been withdrawn!"); //Prevents reentrancy and multiple function calls which steal funds from contract
        withdrawn_commission[msg.sender] = true;
        numRevealedPublic += 1;

        decrypted_r = (decrypted_r ^ Rn) % pk_N; //XOR Rn if it is valid
        balance[msg.sender] += 0.11 ether; // Pay player accordingly (deposit + commission)
        emit logMessage("Successfully revealed Rn");
    }
    // Helper Function - Checks validity of Rn submitted by authority
    function checkChainedEncRn(uint16 Rn, uint[16] memory Y, bytes32[16] memory prevHash) private returns(bool)
    {
        for(uint i = 0; i< 16; i++)
            require(gcd(Y[i], pk_N) == 1, "Not all elements of Y are relatively prime to N");

        uint encRn = 0;
        for(uint16 i=0;i<16;++i)
        {
            if(Rn % 2 == 1)
                encRn = ((Y[i]**2 % pk_N) * pk_x) % pk_N;
            else
                encRn = Y[i]**2 % pk_N;
            Rn/=2;

            // Instead of comparing directly with the hash of each element in encRn, we also take into account prevHash
            // prevHash is obtained during initial commit in function call authorityRn
            // This way, we can keep the integrity of all values of Rn committed by authority
            // Similar to Withdrawing deposit from two banks example taken from lecture
            require(hashEncRn[msg.sender][i] == keccak256(abi.encodePacked(encRn, prevHash[i])));
            hashEncRn[msg.sender][i] = prevHash[i];
        }
        return true;
    }

    // This function is similar to publicRevealHash.
    // However, since authorities control at least t players, it has at least t Rn values.
    // It must submit all Rn starting form the last Rn committed in authroityRn function call
    function authoritiesRevealHash(uint16 Rn, uint[16] memory Y, bytes32[16] memory prevHash) public{
        require(block.number > reveal_r_period && block.number <= reveal_Rn_period);

        // Indicates Rn is encrypted properly and can be hashed to the stored hash in the smart contract
        // Function call only accepted when computed hash matches stored hash in contract
        require(msg.sender == authority); //Access Control
        require(checkChainedEncRn(Rn, Y, prevHash)); 

        // limits the number of function calls as authority to t players. 
        // Smaller than because numRevealedAuthority is initially set to 0
        require(numRevealedAuthority < numAuthorities); 
        numRevealedAuthority += 1; // Counter of number of Rn revealed by authorities

        decrypted_r = (decrypted_r ^ Rn) % pk_N; //XOR Rn if it is valid
        balance[authority] += 0.11 ether; // Pay player accordingly (deposit + commission)
        emit logMessage("Successfully revealed Rn");
    }

    // Normal pull over push implementation of withdrawing balance from contract
    // Used for both bettors and players to withdraw their balance
    function withdrawBalance() public{
        // Player must withdraw before verification_period, otherwise, their balance will be sweept by casino
        require(block.number > deposit_Period && block.number <= verification_period);

        uint amount = balance[msg.sender];
        require(amount > 0, "Empty Balance");
        require(address(this).balance > amount);

        balance[msg.sender] = 0;
        (bool sent, ) = payable(msg.sender).call{value: amount}("");
        require(sent, "Failed to send Schilling!");
    }

    // Casino must reveal secret key when >= one player does not revealed during reveal_Rn_period
    // If the Casino does not use large prime numbers p and q, the quadratic residuousity problem may be broken. 
    // Since the purpose of prime numbers p and q is to prevent decryption by other parties (factoring N is a hard problem), 
    // the casino will never intentionally set non-prime numbers p and q.
    // The checks in revealSecretKey ensures the GM properties hold, but not whether p and q are prime because 
    // it is the casino's responsibility to set p and q prime and prevent attacks by external parties
    // Thus, it checks that secret keys p and q are valid
    function revealSecretKey(uint p, uint q) public {
        require(block.number > reveal_Rn_period && block.number <= reveal_sk_period);

        require((numRevealedPublic < numPublicPlayers )|| (numRevealedAuthority < numAuthorities), "All players have revealed Rn"); 
        require(msg.sender == casinoAddress); //Access Control
        require(!secretKeyRevealed, "Secret Key has been revealed");

        // Casino must not be able to reveal some random secet key and must follow the conditions in GM
        // There is no point if the casino sets p and q to be non-prime as it only eases attack by authority
        // (i) Secret keys are valid are the factors of pk_N
        // (ii) pk_x must not be a quadratic residue with respect to p and q
        require(p * q == pk_N && p > 1 && q > 1);
        require(powmod(pk_x, (p-1)/2, p) != 1);
        require(powmod(pk_x, (q-1)/2, q) != 1);
        secretKeyRevealed = true;

        sk_p = p;
        sk_q = q;
    }

    // Function to declare casino has cheated from not revealing Rand() Parameters or Random Number r or Secret Key SK
    function notRevealed() public {
        require((block.number > reveal_r_period && (!revealedRandParameters || !revealedRandomNumber)) ||
                (block.number > reveal_sk_period && !secretKeyRevealed && ((numRevealedPublic + numRevealedAuthority) < (numPublicPlayers + numAuthorities))));
        
        casinoCheated = true;
    }

    // PHASE 8: Verify RNG and bets are Fair!
    
    // Two methods of verifying RNG depending on whether everyone has revealed Rn
    // If all players have revealed, the function compares decrypted_r (constructed from XOR of all revealed Rn) with revealed_r. 
    // Otherwise, decrypted_r is computed using the revealed secret key.
    function verifyRNG() public
    {
        require(block.number > reveal_sk_period && block.number <= verification_period);

        // If rand() parameters or random numbers have not been revealed by this time, casino has cheated - use notRevealed function
        require(revealedRandParameters, "rand() parameters have not been revealed");
        require(revealedRandomNumber, "random number has not been revealed");
        require(!casinoCheated, "Casino has cheated");
        require(!verifiedRNG);
        
        if(numRevealedPublic == numPublicPlayers && numRevealedAuthority == numAuthorities)
        {
            if(revealed_r != decrypted_r)
                casinoCheated = true;
        }
        else
        {
            // If secret key has not been revealed by this time when at least one player has not revealed Rn, casino has cheated
            require(secretKeyRevealed, "Secret Key not revealed");

            decrypted_r = 0; 
            for(uint i = 0; i < 16; i++)
            {
                uint a = powmod(encrypted_r[i], (sk_p-1)/2, sk_p);
                uint b = powmod(encrypted_r[i], (sk_q-1)/2, sk_q);

                // If encrypted_r[i] is a quadratic residue of p and q, then coressponding bit = 0
                // Otherwise, encrypted_r[i] is not a quadratic residue of p or q and coressponding bit = 1
                if(a != 1 || b != 1)
                {
                    decrypted_r += 2**i;
                }
            }
            if(revealed_r != decrypted_r)
                casinoCheated = true; 
        }
        verifiedRNG = true;
    }

    // Helper Function used to compute rthe pseudorandom value
    function rand(uint k, uint r) private view returns(uint)
    {
        require(revealedRandParameters, "rand() parameters have not been revealed");
        require(revealedRandomNumber, "random number has not been revealed");
        uint seed = k+r; //srand
        uint x = ( seed * rand_a + rand_b ) % rand_n;
        return x;
    }

    // Use rand() parameters and random number given by casino to check whether casino has cheated the bet
    // If casino has cheated bet, the casinoCheated flag will be set to true
    function verifyBet(uint k) public{
        require(block.number > reveal_sk_period && block.number <= verification_period);

        require(verifiedRNG);
        require(msg.sender == owner_k[k]); // Aceces control
        require(!casinoCheated, "Casino has cheated");

        uint rand_result = rand(k, revealed_r);
        if((rand_result%2 == 0 && result_k[k] == false) || (rand_result%2 == 1 && result_k[k] == true)){
            casinoCheated = true;
        }
    }

    // Refund back bettors who lost their bets because casino has cheated
    function cheatRefundPolicy(uint k) public
    {
        // Any time after reveal_sk_period is allowed because casino cannot retrieve their funds anyway
        require(block.number > reveal_sk_period);

        require(casinoCheated);
        require(owner_k[k] == msg.sender);
        require(!cancelledBet[k], "You cancelled the bet. Refund is only for bettors who lost.");
        require(result_k[k] == false, "You won the bet. Refund is only for bettors who lost.");
        require(!cheatRefunded[k], "refund has been completed");
        cheatRefunded[k] = true;

        balance[owner_k[k]] += 0.02 ether;
    }

    // Casino can withdraw deposit after the verification_period if and only if no cheating has been detected
    function casinoWithdrawDeposit() public
    {
        require(block.number > verification_period);

        require(!casinoCheated);
        require(msg.sender == casinoAddress); //Access Control
        (bool sent, ) = casinoAddress.call{value: address(this).balance}("");
        require(sent);
    }

}