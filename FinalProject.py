import random

def generateRandomString(k):
        str = ''
        for i in range(k):
            rand = random.randint()
            str += str(rand % 2)
        return str

class MMAPoracle:
    def __init__(self, k):
        # Initialize the MMAPoracle with key length k and other necessary variables
        self.k = k
        self.IDP = ''  # Identifier
        self.ID = ''   # Secret information
        self.K1 = ''   # Shared key K1
        self.K2 = ''   # Shared key K2
        self.K3 = ''   # Shared key K3
        self.K4 = ''   # Shared key K4

            
    def protocolRun(self):        
        # Step 1: The reader sends a Hello message to the tag, which powers the tag.

        # Step 2: The tag responds with IDP.

        # Step 3: Based on the value of IDP, the reader looks up the values of K1, K2, K3, and K4.
        # The reader then generates two random bit strings n1 and n2 and sends a message to the tag consisting of three bit
        # strings, A = IDP ⊕ K1 ⊕ n1, B = (IDP ∧ K2) ∨ n1, and C = IDP + K3 + n2
        n1 = generateRandomString(self.k)
        n2 = generateRandomString(self.k)
        A = self.IDP ^ self.K1 ^ n1
        B = (self.IDP & self.K2) | n1
        C = self.IDP + self.K3 + n2
        # Messages A and C are used to deliver the random numbers n1 and n2 to the tag without the adversary determining them. 
        # Messages B and D are used to authenticate the reader and tag, respectively. 
        # Message E is used to transmit the tag’s secret information, ID, to the reader.

        # Step 4: Upon receiving A, B, and C, the tag computes n1 = A ⊕ IDP ⊕ K1 and n2 = C − IDP − K3.
        n1 = A ^ self.IDP ^ self.K1
        n2 = C - self.IDP - self.K3 
        # The tag then checks if B = (IDP ∧ K2) ∨ n1. 
        if B == (self.IDP & self.K2) | n1:
            # The tag authenticates the reader and proceeds to the next step. 
            # Step 5: The tag sends a message to the reader consisting of the bit strings D = (IDP ∨ K4) ∧ n2 and E = (ID + IDP) ⊕ n1.
            D = (self.IDP & self.K4) | n2
            E = (self.ID + self.IDP) ^ n1

            # Step 6: The reader computes ID = E ⊕ n1 − IDP.
            computed_ID = E ^ n1 - self.IDP

            #Step 7: The tag and reader each update the values of IDP, K1, K2, K3, and K4.
            self.IDP = (self.IDP + (n1 ^ n2)) ^ self.ID
            self.K1 = self.K1 ^ n2 ^ (self.K3 + self.ID)
            self.K2 = self.K2 ^ n2 ^ (self.K4 + self.ID)
            self.K3 = (self.K3 ^ n1) + (self.K1 ^ self.ID)
            self.K4 = (self.K4 ^ n1) + (self.K2 ^ self.ID)

        else:
            # Otherwise the tag terminates the protocol.




        return outStruct, self  # Return the output structure and the updated oracle

    def verifyID(self, given_ID):
        # Implement the function to verify if the given ID is the true ID of the tag
        # Return 1 if correct, 0 otherwise
        return self.ID == given_ID
    

class EMAPoracle:
    def __init__(self, k):
        # Initialize the EMAPoracle with key length k and other necessary variables
        self.k = k
        self.IDP = ''  # Identifier
        self.ID = ''   # Secret information
        self.K1 = ''   # Shared key K1
        self.K2 = ''   # Shared key K2
        self.K3 = ''   # Shared key K3
        self.K4 = ''   # Shared key K4


    def protocolRun(self):
        # Step 1: The reader sends a Hello messgae to the tag, which powers the tag.
        # Step 2: The tag responds with IDP.
        # Step 3: Based on the value of IDP, the reader looks up the values of K1, K2, K3, and K4. 
        # The reader generates two random bit strings n1 and n2 and sends a message to the tag consisting of three bit strings,
        # A = IDP ⊕ K1 ⊕ n1, B = (IDP ∨ K2) ⊕ n1, and C = IDP ⊕ K3 ⊕ n2.
        n1 = generateRandomString(self.k)
        n2 = generateRandomString(self.k)
        A = self.IDP ^ self.K1 ^ n1
        B = (self.IDP & self.K2) | n1
        C = self.IDP ^ self.K3 ^ n2

        # Step 4: The tag computes n1 = A⊕IDP ⊕ K1 and n2 = C ⊕IDP ⊕ K3, and checks if B = (IDP ∧ K2)⊕n1.
        # If the authentication check is passed, then the tag sends a message to the reader containing the bit
        # strings D = (IDP ∧ K4) ⊕ n2 and E = (IDP ∧ n1 ∨ n2) ⊕ ID ⊕ K1 ⊕ K2 ⊕ K3 ⊕ K4.
        # Step 5: The reader computes ID using the received message E.
        # Step 6: The tag and reader each update the values of IDP, K1, K2, K3, and K4 as follows:

        # The notation Fp is defined as follows. If x is a bit string, where the length of x is a multiple of 4, then
        # Fp(x) is computed by first dividing x into 4-bit blocks. The four bits in each block are then XORed.
        # For example, if x = 1011 0110 1000, then Fp(x) = 101. The notation (ID)1:48 refers to the 48 most
        # significant bits of ID, while (ID)49:96 denotes the 49 least significant bits of ID. As in MMAP, the
        # ID is unchanged.
        return outStruct, self  # Return the output structure and the updated oracle

    def impersonate_reader(self, A, B, C):
        # Implement the function to impersonate the reader in EMAP protocol
        # Return D and E based on the received messages A, B, and C
        # ...


    def verifyID(self, given_ID):
        # Implement the function to verify if the given ID is the true ID of the tag
        # Return 1 if correct, 0 otherwise
        return self.ID == given_ID
