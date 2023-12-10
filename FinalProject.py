import random
k = 16

band = lambda str1, str2: bin((int(str1, 2) & int(str2, 2)) % (2**k))[2:].zfill(k)
bor = lambda str1, str2: bin((int(str1, 2) | int(str2, 2)) % (2**k))[2:].zfill(k)
bxor = lambda str1, str2: bin((int(str1, 2) ^ int(str2, 2)) % (2**k))[2:].zfill(k)
badd = lambda str1, str2: bin((int(str1, 2) + int(str2, 2)) % (2**k))[2:].zfill(k)
bneg = lambda str1: ''.join('1' if bit == '0' else '0' for bit in str1)

# this function takes an in integer value k, and returns a random string of 1s and 0s of length k
def generateRandomString(k):
        strr = ''
        for i in range(k):
            randnum = random.randint(0,100)
            strr += str(randnum % 2)
        return strr

class MMAPoracle:
    def __init__(self, k, IDP, ID, K1, K2, K3, K4):
        # Initialize the MMAPoracle with key length k and other necessary variables
        self.k = k
        self.IDP = IDP  # Identifier
        self.ID = ID   # Secret information
        self.K1 = K1   # Shared key K1
        self.K2 = K2   # Shared key K2
        self.K3 = K3   # Shared key K3
        self.K4 = K4   # Shared key K4
            
    def protocolRun(self):    
        # Step 1: The reader sends a Hello message to the tag, which powers the tag.

        # Step 2: The tag responds with IDP.

        # Step 3: Based on the value of IDP, the reader looks up the values of K1, K2, K3, and K4.
        # The reader then generates two random bit strings n1 and n2 and sends a message to the tag consisting of three bit
        # strings, A = IDP ⊕ K1 ⊕ n1, B = (IDP ∧ K2) ∨ n1, and C = IDP + K3 + n2
        n1 = generateRandomString(self.k)
        n2 = generateRandomString(self.k)

        A = bxor(bxor(self.IDP, self.K1), n1)
        B = bor(band(self.IDP, self.K2), n1)
        C = badd(badd(self.IDP, self.K3), n2)

        # Messages A and C are used to deliver the random numbers n1 and n2 to the tag without the adversary determining them. 
        # Messages B and D are used to authenticate the reader and tag, respectively. 
        # Message E is used to transmit the tag’s secret information, ID, to the reader.

        # Step 4: Upon receiving A, B, and C, the tag computes n1 = A ⊕ IDP ⊕ K1 and n2 = C − IDP − K3.
        new_n1 = bxor(bxor(A, self.IDP), self.K1)
        new_n2 = badd(badd(C, bneg(self.IDP)), bneg(self.K3))

        # The tag then checks if B = (IDP ∧ K2) ∨ n1. 
        if B == bor(band(self.IDP,self.K2), new_n1):

            # The tag authenticates the reader and proceeds to the next step. 
            # Step 5: The tag sends a message to the reader consisting of the bit strings D = (IDP ∨ K4) ∧ n2 and E = (ID + IDP) ⊕ n1.
            D = band(bor(self.IDP, self.K4), new_n2)
            E = bxor(badd(self.ID, self.IDP), new_n1)


            # Step 6: The reader computes ID = E ⊕ n1 − IDP.
            computed_ID = badd(bxor(E, n1),bneg(self.IDP))

            #Step 7: The tag and reader each update the values of IDP, K1, K2, K3, and K4.
            self.IDP = bxor(badd(self.IDP, bxor(n1, n2)), self.ID)
            self.K1 = bxor(bxor(self.K1, n2), badd(self.K3, self.ID))
            self.K2 = bxor(bxor(self.K2, n2), badd(self.K4, self.ID))
            self.K3 = badd(bxor(self.K3, n1), bxor(self.K1, self.ID))
            self.K4 = badd(bxor(self.K4, n1), bxor(self.K2, self.ID))

        else:
            # Otherwise the tag terminates the protocol.
            print("terminating protocol")

        outStruct = {"A": A,
                     "B": B,
                     "C": C,
                     "D": D,
                     "E": E,}
        
        return outStruct, self  # Return the output structure and the updated oracle

    def verifyID(self, given_ID):
        # Implement the function to verify if the given ID is the true ID of the tag
        # Return 1 if correct, 0 otherwise
        return self.ID == given_ID

# MMAP Attack 

# Eve has access to B and IDP
# any bits of n1 corresponding to 0 bits of IDP are known to Eve
# ID = (E XOR n1) - IDP 
# runs until it knows all bits of ID
def MMAP_Attack(oracle):
    # Eve already knows IDP because it is a non-secret pseudonym
    outStruct, __ = oracle.protocolRun()
    # EVE has access to B = (IDP and  K2) or n1
    # and IDP 

    IDP = oracle.IDP
    
    B = outStruct.get('B')

    N1 = ""
    for i in range(oracle.k):
        if IDP[i] == '0':
            N1 += B[i]
        else:
            N1 += 'X'

    # if IDP[i] = 0 then B[i] = N1[i] 
    
    # EVE also knows E
    E = outStruct.get('E')

    E_XOR_n1 = ""
    for i in range(k):
        if N1[i] =='X':
            E_XOR_n1 += 'X'
        elif N1[i] == E[i]:
            E_XOR_n1 += '0'
        else: #N1[i] != E[i]
            E_XOR_n1 += '1'
    
    # make IDP negative
    NIDP = bneg(IDP)
    print("CHECKING NEAGTIVE FOR IDP")
    print("IDP  =", IDP)
    print("NIDP =", NIDP)
    
    ID = ""
    carry = 0
    for i in range(k):
        if E_XOR_n1[i] == 'X':
            ID += 'X'
            carry = 0
        else:
            curr_add = (int(E_XOR_n1[i]) + int(NIDP[i]) + carry)
            if curr_add > 1:
                carry = 1
            else:
                carry = 0
            ID += str(curr_add % 2)

    return ID


def runMMAPAttack():
    k = 16
    IDP = generateRandomString(k)
    ID = generateRandomString(k)
    K1 = generateRandomString(k)
    K2 = generateRandomString(k)
    K3 = generateRandomString(k)
    K4 = generateRandomString(k)

    EVE_ID = 'X' * k

    oracle = MMAPoracle(k, IDP, ID, K1, K2, K3, K4)
    print("REAL ID =", oracle.ID)
    print()
    i = 1
    while 'X' in EVE_ID:
        print("Iteration", i)
        print("EVE ID =", EVE_ID)
        print()
        i = i + 1

        curr_ID = MMAP_Attack(oracle)
        print()
        print("REAL ID =", oracle.ID)
        print("CURR ID =", curr_ID)

        newID = ""
        for i in range(oracle.k):
            if EVE_ID[i] == 'X':
                newID += curr_ID[i]
            else:
                newID += EVE_ID[i]

        EVE_ID = newID
        print()
    print("ID = ", EVE_ID)
    print()
    print("Verfication is ", oracle.verifyID(EVE_ID))
    

runMMAPAttack()
