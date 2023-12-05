import random

# this function takes an in integer value k, and returns a random string of 1s and 0s of length k
def generateRandomString(k):
        strr = ''
        for i in range(k):
            randnum = random.randint(0,100)
            strr += str(randnum % 2)
        return strr

band = lambda str1, str2: bin((int(str1, 2) & int(str2, 2)) % (2 ** k))[2:].zfill(k)
bor = lambda str1, str2: bin((int(str1, 2) | int(str2, 2)) % (2 ** k))[2:].zfill(k)
bxor = lambda str1, str2: bin((int(str1, 2) ^ int(str2, 2)) % (2 ** k))[2:].zfill(k)
badd = lambda str1, str2: bin((int(str1, 2) + int(str2, 2)) % (2 ** k))[2:].zfill(k)
bsub = lambda str1, str2: bin((int(str1, 2) - int(str2, 2)) % (2 ** k))[2:].zfill(k)



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
        print("Created MMAP protocol")
        print()

            
    def protocolRun(self):  
        print("Running protocol")   
        print()   
        # Step 1: The reader sends a Hello message to the tag, which powers the tag.
        print("Step 1: The reader sends a Hello message to the tag, which powers the tag.")
        print()
        # Step 2: The tag responds with IDP.
        print("Step 2: The tag responds with IDP.")
        print()

        # Step 3: Based on the value of IDP, the reader looks up the values of K1, K2, K3, and K4.
        # The reader then generates two random bit strings n1 and n2 and sends a message to the tag consisting of three bit
        # strings, A = IDP ⊕ K1 ⊕ n1, B = (IDP ∧ K2) ∨ n1, and C = IDP + K3 + n2
        print("Step #3")
        n1 = generateRandomString(self.k)
        n2 = generateRandomString(self.k)
        print("n1 =", n1)
        print("n2 =", n2)
        A = bxor(self.IDP, bxor(self.K1, n1))
        B = bor(band(self.IDP, self.K2), n1)
        C = badd(badd(self.IDP, self.K3), n2)
        print("A =", A)
        print("B =", B)
        print("C =", C)
        print()
        # Messages A and C are used to deliver the random numbers n1 and n2 to the tag without the adversary determining them. 
        # Messages B and D are used to authenticate the reader and tag, respectively. 
        # Message E is used to transmit the tag’s secret information, ID, to the reader.

        # Step 4: Upon receiving A, B, and C, the tag computes n1 = A ⊕ IDP ⊕ K1 and n2 = C − IDP − K3.
        print("Step #4")
        new_n1 = bxor(bxor(A, self.IDP), self.K1)
        new_n2 = bsub(bsub(C, self.IDP), self.K3)
        print("Caclulated n1 =", new_n1)
        print("Caclulated n2 =", new_n2)
        print()
        # The tag then checks if B = (IDP ∧ K2) ∨ n1. 
        if B == bor(band(self.IDP,self.K2), n1):
            print("B statement is true")
            print()
            # The tag authenticates the reader and proceeds to the next step. 
            # Step 5: The tag sends a message to the reader consisting of the bit strings D = (IDP ∨ K4) ∧ n2 and E = (ID + IDP) ⊕ n1.
            print("Step 5")
            D = bor(band(self.IDP, self.K4), n2)
            E = bxor(badd(self.ID, self.IDP), n1)
            print("D =", D)
            print("E =", E)
            print()

            # Step 6: The reader computes ID = E ⊕ n1 − IDP.
            computed_ID = bsub(bxor(E, n1),self.IDP)
            print("Step #6")
            print("computed ID =", computed_ID)
            print()

            #Step 7: The tag and reader each update the values of IDP, K1, K2, K3, and K4.
            print("Step #7")
            self.IDP = bxor(badd(self.IDP, bxor(n1, n2)), self.ID)
            self.K1 = bxor(bxor(self.K1, n2), badd(self.K3, self.ID))
            self.K2 = bxor(bxor(self.K2, n2), badd(self.K4, self.ID))
            self.K3 = badd(bxor(self.K3, n1), bxor(self.K1, self.ID))
            self.K4 = badd(bxor(self.K4, n1), bxor(self.K2, self.ID))

            print("IDP =", self.IDP)
            print("K1  =", self.K1)
            print("K2  =", self.K2)
            print("K3  =", self.K3)
            print("K4  =", self.K4)
            print()

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

# Example values for ID, IDP, K1, K2, K3, K4, and k (length of bit strings)
ID = "1101"  # Example 4-bit ID
IDP = "0011" # Example 4-bit IDP
K1 = "0101"  # Example 4-bit key K1
K2 = "1010"  # Example 4-bit key K2
K3 = "1100"  # Example 4-bit key K3
K4 = "1001"  # Example 4-bit key K4
k = 4        # Length of the bit strings

# Create an instance of MMAPoracle
mmap_oracle = MMAPoracle(k, IDP, ID, K1, K2, K3, K4)

# Run the protocol
protocol_output = mmap_oracle.protocolRun()

# Check if protocol_output is None (which indicates an error in authentication)
if protocol_output:
    print("Protocol Output:", protocol_output)
    print()

    # Verify the ID
    is_id_correct = mmap_oracle.verifyID(ID)
    print("Is the ID correct?", is_id_correct)
    print()
else:
    print("Authentication failed during the protocol run.") 


def MMAP_attack(oracle):
    """
    MMAP Attack to recover the secret ID using observations on B and IDP.
    """
    # Step 1: Eavesdrop on the protocol and observe B and IDP
    outStruct, _ = oracle.protocolRun()
    B = outStruct["B"]
    IDP = oracle.IDP

    # Step 2: Recover bits of n1 based on B and IDP
    n1_recovered = "".join(['0' if IDP[i] == '0' else B[i] for i in range(len(B))])

    # Step 3: Use the recovered n1 to determine ID based on E
    E = outStruct["E"]
    ID_recovered = bin(int(E, 2) ^ int(n1_recovered, 2) - int(IDP, 2))[2:].zfill(len(IDP))

    return ID_recovered

# Example of using the MMAP_attack function
def run_MMAP_attack():
    k = 16  # Set the desired length of bit strings
    IDP = generateRandomString(k)
    ID = generateRandomString(k)
    K1 = generateRandomString(k)
    K2 = generateRandomString(k)
    K3 = generateRandomString(k)
    K4 = generateRandomString(k)

    # Create an instance of MMAPoracle
    oracle = MMAPoracle(k, IDP, ID, K1, K2, K3, K4)

    print("Original ID:", ID)

    # Run the MMAP_attack to recover the secret ID
    recovered_ID = MMAP_attack(oracle)

    print("Recovered ID:", recovered_ID)

    # Verify the correctness of the recovered ID
    if oracle.verifyID(recovered_ID):
        print("Verification: Successful")
    else:
        print("Verification: Failed")

# Run the example
run_MMAP_attack()
