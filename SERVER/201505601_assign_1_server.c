
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <stdlib.h>
#include <time.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/sha.h>

/* Global constants  #include <openssl/sha.h>*/
#define SERVICE_PORT 8992
#define MAX_SIZE 20
#define Q_SIZE 5

#define SUCCESS 1
#define FAIL 0

#define STACK_SIZE 10000
  #define div /
  #define mod %

#define DEFAULT_SERVER "127.0.0.1"

#define PUBKEY 10	/* PUBKEY MSG*/
#define REPCOM 40  	/* ReSPONSE COMPLETE message */
#define REP 30  	/* Reply message */
#define DIS 50   /* DISCONNECT*/


#define SERVICE_PORT_1 8996

#define MAX_LEN 1024

  
  #define NOT_EXIST 0xFFFF;
  #define LARGE 199
  #define MAX_ITERATION 10
  // Max tests in Miller-Robin Primality Test.
  #define div /
  #define mod %
  #define and &&
  #define true 1
  #define false 0


/* Define a message structure */

int hashArr[125];

  typedef short boolean;

      typedef union
  {
    struct
    {
      long int n;
      long int e;
    } public_key;

    struct
    {
      long int n;
      long int d;
    } private_key;
  } key;

  typedef struct {
   int opcode;
   int src_addr;
   int dest_addr;
   } Hdr;

  /* REP message */
  typedef struct {
   //int status;
   long int ci_txt;
   char sha_buf[1000];
  } Rep_Msg;

   /* DISCONNECT message */
  typedef struct {
   char err_msg[100];
  } Dis_Connect;

   /* PUBLIC KEY message */
  typedef struct
    {
      long int n;
      long int e;
    } Public_Key;

    /* REQ message */
  typedef struct {
    Public_Key pubkey;
   char fileName[100];
  } Req_Msg;
  
  typedef union {
      Req_Msg req;
      Rep_Msg reply;
      Dis_Connect dis;
  } AllMsg;

  /*A general message */
  typedef struct {
  Hdr hdr; /* Header for a message */
   AllMsg al_msg;
  } Msg;

typedef struct
  {
    int top;
    char c[STACK_SIZE];
  } stack;

  stack s;
/* Function prototypes */
int startServer ( );
void Talk_to_client ( int );
void serverLoop ( int );
void close(int);
int fork();
void initEncodingTable();
long int EncryptionAlgorithm( long int M, key pub_key);
long int ModPower(long int x, long int e, long int n);
void decimal_to_binary(long int n, char str[]);
  void reverse_string(char x[]);
  
/* Start the server: socket(), bind() and listen() */
int startServer ()
{
   int sfd;                    /* for listening to port PORT_NUMBER */
   struct sockaddr_in saddr;   /* address of server */
   int status;

   /* Request for a socket descriptor */
   sfd = socket(AF_INET, SOCK_STREAM, 0);
   if (sfd == -1) {
      fprintf(stderr, "*** Server error: unable to get socket descriptor\n");
      exit(1);
   }

   /* Set the fields of server's internet address structure */
   saddr.sin_family = AF_INET;            /* Default value for most applications */
   saddr.sin_port = htons(SERVICE_PORT);  /* Service port in network byte order */
   saddr.sin_addr.s_addr = INADDR_ANY;    /* Server's local address: 0.0.0.0 (htons not necessary) */
   bzero(&(saddr.sin_zero),8);            /* zero the rest of the structure */

   /* Bind the socket to SERVICE_PORT for listening */
   status = bind(sfd, (struct sockaddr *)&saddr, sizeof(struct sockaddr));
   if (status == -1) {
      fprintf(stderr, "*** Server error: unable to bind to port %d\n", SERVICE_PORT);
      exit(2);
   }

   /* Now listen to the service port */
   status = listen(sfd,Q_SIZE);
   if (status == -1) {
      fprintf(stderr, "*** Server error: unable to listen\n");
      exit(3);
   }

   fprintf(stderr, "+++ Server successfully started, listening to port %hd\n", SERVICE_PORT);
	//printf("sfd value is: %d", &sfd); 
   return sfd;
}


/* Accept connections from clients, spawn a child process for each request */
void serverLoop ( int sfd )
{

	  int cfd;                    /* for communication with clients */
   struct sockaddr_in caddr;   /* address of client */
   int size;


    while (1) {
      /* accept connection from clients */
      cfd = accept(sfd, (struct sockaddr *)&caddr, &size);
      if (cfd == -1) {
         fprintf(stderr, "*** Server error: unable to accept request\n");
         continue;
      }

     printf("**** Connected with %s\n", inet_ntoa(caddr.sin_addr));
     
      /* fork a child to process request from client */
      if (!fork()) {
         Talk_to_client (cfd);
         fprintf(stderr, "**** Closed connection with %s\n", inet_ntoa(caddr.sin_addr));
         close(cfd);
         exit(0);
      }

      /* parent (server) does not talk with clients */
      close(cfd);

      /* parent waits for termination of child processes */
      while (waitpid(-1,NULL,WNOHANG) > 0);
   }
}


/* Interaction of the child process with the client */
void Talk_to_client ( int cfd )
{
   int status;
   int nbytes;
   int src_addr, dest_addr;

   long int plaintext, ciphertext;
  // int chk1, chk2; 
  //  ReqMsg send_msg;
  //  RepMsg recv_msg;
    Msg gen_Msg;
    key pub_key;
   // AllMsg al_msg;

  char buff[3];
  int encoded_buff[3];
  FILE *fptr;
  int index = 0;

   dest_addr = inet_addr("127.0.0.1");
   src_addr = inet_addr("DEFAULT_SERVER");
 
   while (1) {
   /* Receive response from server */
   nbytes = recv(cfd, &gen_Msg, sizeof(Msg), 0);
   printf("Recieved DATA");
   if (nbytes == -1) {
      fprintf(stderr, "*** Server error: unable to receive\n");
      return;
   }
   
   switch ( gen_Msg.hdr.opcode ) {
    
   case PUBKEY : /* Request message */
              printf("%d",gen_Msg.hdr.src_addr);
              printf("\nMessage:: with opcode %d (PUBKEY) received from source (%d) is\n", gen_Msg.hdr.opcode, gen_Msg.hdr.src_addr);  
             
                fptr = fopen(gen_Msg.al_msg.req.fileName,"r");
                  if (!fptr){
                     printf("\n Error in opening file, No file exists hence DISCONNECT \n");
                      /* send the reply message REP to the server */

                     gen_Msg.hdr.opcode = DIS;
                     gen_Msg.hdr.src_addr = src_addr;        
                     gen_Msg.hdr.dest_addr = dest_addr;

                     strcpy(gen_Msg.al_msg.dis.err_msg , "\n No file exists hence DISCONNECT");
                     
                      //printf("Sending the reply message REP to the client \n"); 
                      status = send(cfd, &gen_Msg, sizeof(Msg), 0);
                       if (status == -1) {
                        fprintf(stderr, "*** Client error: unable to send\n");
                        exit(1);
                        }

                        exit(0);
                  }
                  else{

                      printf("\n Public Key received from client is <%ld, %ld> \n", gen_Msg.al_msg.req.pubkey.n, gen_Msg.al_msg.req.pubkey.e);  
              
                      printf("\n Filename received from client, to be shared securely is : %s\n\n", gen_Msg.al_msg.req.fileName);
                      printf("\n Processing File for Transer, doing Encryption and Encoding\n ");
                       pub_key.public_key.n =  gen_Msg.al_msg.req.pubkey.n;
                       pub_key.public_key.e = gen_Msg.al_msg.req.pubkey.e;

		      printf("\nSending the response message REP to the CLIENT\n");    
                     while (fgets(buff,3, fptr)!=NULL){
                    
                      if(strlen(buff) < 2){
                        buff[1] = ' ';
                       }

                      index = buff[0];
                      encoded_buff[0] = hashArr[index];
                     // printf("encoded_buff[0] is ##%d##", encoded_buff[0]);
                       index = buff[1];
                      encoded_buff[1] = hashArr[index];
                     // printf("encoded_buff[1] is ##%d##", encoded_buff[1]);
                     
                      plaintext = (encoded_buff[0] * 100) + encoded_buff[1];
                        
                    //  printf("\n plainText is %ld\n", plaintext);

                       ciphertext = EncryptionAlgorithm(plaintext, pub_key);
                     //  printf("\n ciphertext is %ld\n", ciphertext);

                  //     printf("here buff is ##%s##\n and its len is %d", buff, strlen(buff));
                      
                        
                       unsigned char temp[SHA_DIGEST_LENGTH];
                       char newbuf[SHA_DIGEST_LENGTH*2];

                        memset(newbuf, 0x0, SHA_DIGEST_LENGTH*2);
                        memset(temp, 0x0, SHA_DIGEST_LENGTH);
 
                        SHA1((unsigned char *)buff, strlen(buff), temp);
 
                         int i = 0;
                        for (i=0; i < SHA_DIGEST_LENGTH; i++) {
                            sprintf((char*)&(newbuf[i*2]), "%02x", temp[i]);
                        }


                      //  printf("SHA1 of %s is %s\n", buff, newbuf);
                         gen_Msg.hdr.opcode = REP; 
                         gen_Msg.hdr.src_addr = src_addr;        
                         gen_Msg.hdr.dest_addr = dest_addr;
                       
                         gen_Msg.al_msg.reply.ci_txt = ciphertext;
                         strcpy(gen_Msg.al_msg.reply.sha_buf, newbuf);

                      status = send(cfd, &gen_Msg, sizeof(Msg), 0);
                       if (status == -1) {
                        fprintf(stderr, "*** Client error: unable to send\n");
                        exit(1);
                        }
                  }
                    fclose(fptr);   
              }  

                         gen_Msg.hdr.opcode = REPCOM; 
                         gen_Msg.hdr.src_addr = src_addr;        
                         gen_Msg.hdr.dest_addr = dest_addr;
                         status = send(cfd, &gen_Msg, sizeof(Msg), 0);
                       if (status == -1) {
                        fprintf(stderr, "*** Client error: unable to send\n");
                        exit(1);
                        } 
                        
                        break;

    case DIS : printf("Message:: with opcode %d (DIS) received from client (%d) is: ", gen_Msg.hdr.opcode, gen_Msg.hdr.src_addr);  
               printf("%s\n", gen_Msg.al_msg.dis.err_msg );
               exit(0);
    default: 
           printf("message received with opcode: %d\n", gen_Msg.hdr.opcode);
           exit(0);  
   }
 }
}

int main (int argc, char *argv[] )
{
   // int sfd;
   // initEncodingTable();
   // printf("Initialised Encodings Table\n");
  
   //  sfd = startServer();  
   //  serverLoop(sfd);
   
    char sip[16];
   int cfd;
   initEncodingTable();
 
   strcpy(sip, (argc == 2) ? argv[1] : DEFAULT_SERVER);
   cfd = serverConnect(sip);
  
   key pub_key, pvt_key;
  
  printf("\nKey generation has been started by Client:\n\r");

  int check = KeyGeneration(&pub_key, &pvt_key);
  while(!check){
    check = KeyGeneration(&pub_key, &pvt_key);
  }
  
  printf("\nPublic Key of Client is (n,e): (%ld,%ld)\n\r", pub_key.public_key.n, pub_key.public_key.e);
  printf("\nPrivate key of Client is (n,d): (%ld,%ld)\n\r", pvt_key.private_key.n,pvt_key.private_key.d);

  Talk_to_server (cfd,  pub_key.public_key.n,  pub_key.public_key.e, pvt_key);
    close(cfd);
     return 0;

}

void initEncodingTable(){
        int i=0;

  for(i=0;i< 125; i++)
    hashArr[i] = 0;

  int val = 1;
 for(i=65; i <= 90; i++){
        hashArr[i] = val;
        val++;
   }

   hashArr[10] = 67;//newline character
   hashArr[32] = 66;//space
   hashArr[33] = 65;
   hashArr[44] = 63;
   hashArr[46] = 64;

   val = 53;
   for(i=48;i<=57; i++){
     hashArr[i] = val;
        val++;
   }
    
  
  
   val = 27;
   for(i=97; i <= 122; i++){
        hashArr[i] = val;
        val++;
   }

    /*for(i=0;i< 125; i++)
      printf("i is %d and hash[i] is%d \n", i, hashArr[i] );*/

}

// Encryption Algorithm(E)
  long int EncryptionAlgorithm(long int M, key pub_key)
  {
    // Alice computes ciphertext as C := M^e(mod n) to Bob.
    long int C;
   
    //printf("\nEncryption keys= (%ld,%ld)\n\r",pub_key.public_key.n,pub_key.public_key.e);
    C = ModPower(M, pub_key.public_key.e, pub_key.public_key.n);
    return C;
  }

  // Algorithm: Modular Power: x^e(mod n).
  long int ModPower(long int x, long int e, long int n)
  {
    // To calculate y:=x^e(mod n).
    //long y;
    long int y;
    long int t;
    int i;
    int BitLength_e;
    char b[STACK_SIZE];
    //printf("e(decimal) = %ld\n",e);
    decimal_to_binary(e,b);
    
      BitLength_e = strlen(b);
      y = x;
      reverse_string(b);
      for(i = BitLength_e -2; i >= 0; i--)
      {
        if(b[i] == '0')
          t = 1;
        else
          t = x;

        y = (y * y) mod n;
  
        if( y < 0) {
          y = -y;
          y = (y - 1) * (y mod n) mod n;
          printf("y is negative\n");
        }
        y = (y*t) mod n;
  
        if ( y < 0) {
          y = -y;
          y = (y - 1) * (y mod n) mod n;
          printf("y is negative\n");
        }
      }
  
      if( y < 0) {
        y = -y;
        y = (y -1) * (y mod n) mod n;
        printf("y is negative\n");
      }
      return y;
  }
// end of ModPower().

void decimal_to_binary(long int n, char str[])
  {
    // n is the given decimal integer.
    // Purpose is to find the binary conversion
    // of n.
    // Initialise the stack.
    int r;
    s.top = 0;
    while (n != 0 )
    {
      r = n mod 2;
      s.top++;
      if(s.top >= STACK_SIZE)
      {
        printf("\nstack overflown!\n");
        return;
      }
      s.c[s.top] = r + 48;
        n = n div 2;
      }
      while(s.top)
      {
        *str++ = s.c[s.top--];
      }
        *str= '\0';
      return ;
    }
    // Algorithm: reverse a string.
    void reverse_string(char x[])
    {
      int n = strlen(x)- 1;
      int i = 0;
      char temp[STACK_SIZE];

      for(i = 0; i<=n; i++)
      temp[i] = x[n-i];

      for(i=0 ; i<=n; i++)
      x[i] = temp[i];
    }

/*** End of server.c ***/     

/* code to make it behave lika a client and recieve*/
/* Global constants */

/* Define a message structure */


/*@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ ADDED HERE*/
  
  int mul_inverse=0;
  int gcd_value;
  stack s;

  
  long int ModPower(long int x,long int e, long int n);
  boolean MillerRobinTest(long int n, int iteration);
  boolean verify_prime(long int p);

  int KeyGeneration(key *pub_key, key *pvt_key);
  long int DecryptionAlgorithm( long int C, key pvt_key);

/**********@@@@@@@@@@@@@@@@@ TILL HERE */
/* Function prototypes */
int serverConnect ( char * );
void Talk_to_server ( int, long int n, long int e, key pvt_key);
void close(int);




/* Connect with the server: socket() and connect() */
int serverConnect ( char *sip )
{
   int cfd;
   struct sockaddr_in saddr;   /* address of server */
   int status;

   /* request for a socket descriptor */
   cfd = socket (AF_INET, SOCK_STREAM, 0);
   if (cfd == -1) {
      fprintf (stderr, "*** Client error: unable to get socket descriptor\n");
      exit(1);
   }

   /* set server address */
   saddr.sin_family = AF_INET;              /* Default value for most applications */
   saddr.sin_port = htons(SERVICE_PORT_1);    /* Service port in network byte order */
   saddr.sin_addr.s_addr = inet_addr(sip);  /* Convert server's IP to short int */
   bzero(&(saddr.sin_zero),8);              /* zero the rest of the structure */

   /* set up connection with the server */
   status = connect(cfd, (struct sockaddr *)&saddr, sizeof(struct sockaddr));
   if (status == -1) {
      fprintf(stderr, "*** Client error: unable to connect to server\n");
      exit(1);
   }

   fprintf(stderr, "Connected to server\n");

   return cfd;
}

/* Interaction with the server */
void Talk_to_server ( int cfd, long int n, long int e , key pvt_key)
{
   //char buffer[MAX_LEN];
   int nbytes, status;
   int src_addr, dest_addr;
   long int ciphertext, deciphertext;
  Msg gen_Msg;


   dest_addr = inet_addr("DEFAULT_SERVER");
   src_addr = inet_addr("127.0.0.1");

   /* send the request message REQ to the server */
   printf("\n Sending the request message REQ to the server\n");          
   gen_Msg.hdr.opcode = PUBKEY;
   gen_Msg.hdr.src_addr = src_addr;
   gen_Msg.hdr.dest_addr = dest_addr;
   
   gen_Msg.al_msg.req.pubkey.n = n;
   gen_Msg.al_msg.req.pubkey.e = e;

    strcpy(gen_Msg.al_msg.req.fileName , "newFile.txt"); 

   status = send(cfd, &gen_Msg, sizeof(Msg), 0);
   if (status == -1) {
      fprintf(stderr, "*** Server error: unable to send\n");
      return;
    }

  while (1) {
  /* receive greetings from server */
   nbytes = recv(cfd, &gen_Msg, sizeof(Msg), 0);
   if (nbytes == -1) {
      fprintf(stderr, "*** Client error: unable to receive\n");
      
   }
   int index=0; 
   long int num1=0, num2=0;
   char buff[3];
   int answer=0;
 
  FILE *fptr;
   switch ( gen_Msg.hdr.opcode ) {
    
   case REP : //printf("Message:: with opcode %d (REP) received from source (%d)\n", gen_Msg.hdr.opcode, gen_Msg.hdr.src_addr);  
              
              ciphertext = gen_Msg.al_msg.reply.ci_txt;
              deciphertext = DecryptionAlgorithm(ciphertext, pvt_key);
             // printf("\n deciphertext is %ld and ciphertext is %ld \n", deciphertext, ciphertext);
              num1 = deciphertext/100;
             // printf("\n num1 is %ld\n", num1);
              num2 = deciphertext%100;
            //  printf("\n num2 is %ld\n", num2);

               for(index=0; index < 125; index++){
                  if(hashArr[index] == num1){
                    buff[0] = index;
                  }
                  if(hashArr[index] == num2){
                    buff[1] = index;
                  }
              }
              buff[2] = 0; 
              //printf("%s\n", buff);

                unsigned char temp[SHA_DIGEST_LENGTH];
                       char newbuf[SHA_DIGEST_LENGTH*2];

                        memset(newbuf, 0x0, SHA_DIGEST_LENGTH*2);
                        memset(temp, 0x0, SHA_DIGEST_LENGTH);
 
                        SHA1((unsigned char *)buff, strlen(buff), temp);
 
                         int i = 0;
                        for (i=0; i < SHA_DIGEST_LENGTH; i++) {
                            sprintf((char*)&(newbuf[i*2]), "%02x", temp[i]);
                        }


                       // printf(" generated here SHA1 of ##%s## is %s\n", buff, newbuf);
                       // printf(" received here SHA1 is %s\n", gen_Msg.al_msg.reply.sha_buf);

                        answer = strcmp(newbuf,gen_Msg.al_msg.reply.sha_buf);
                       // printf("ans is %d \n", answer);
            if (answer==0) {

                // write buff to a file;
                   fptr=fopen("newFile.txt","a");
                   if(fptr==NULL){
                      printf("Error creating a file!");
                      exit(1);
                   }
                   
                   fprintf(fptr,"%s", buff);
                   fclose(fptr);
            }
            else {
              // send a disconnect message to server.
                 gen_Msg.hdr.opcode = DIS;
                           gen_Msg.hdr.src_addr = src_addr;        
                           gen_Msg.hdr.dest_addr = dest_addr;

                           strcpy(gen_Msg.al_msg.dis.err_msg , "\n SHA1 DIGEST has a Mismatch");
                           status = send(cfd, &gen_Msg, sizeof(Msg), 0);
                             if (status == -1) {
                              fprintf(stderr, "*** Client error: unable to send\n");
                              exit(1);
                              }
             }
              
            break;
   case DIS : printf("\nMessage:: with opcode %d (DIS) received from source (%d) is: ", gen_Msg.hdr.opcode, gen_Msg.hdr.src_addr);  
          printf("%s\n", gen_Msg.al_msg.dis.err_msg );
            exit(0);

   case REPCOM : printf("\n Message:: with opcode %d (REPCOM) received from source (%d) is: ", gen_Msg.hdr.opcode, gen_Msg.hdr.src_addr);  
             printf("\n Complete message received.\n");
                       gen_Msg.hdr.opcode = DIS;
                           gen_Msg.hdr.src_addr = src_addr;        
                           gen_Msg.hdr.dest_addr = dest_addr;

                           strcpy(gen_Msg.al_msg.dis.err_msg , "\n Complete message received, now we are Dis-connecting.");
                           status = send(cfd, &gen_Msg, sizeof(Msg), 0);
                             if (status == -1) {
                              fprintf(stderr, "*** Client error: unable to send\n");
                              exit(1);
                              }
             exit(0);
   default: 
           printf("message received with opcode: %d\n", gen_Msg.hdr.src_addr);
           exit(0);  
   }
 }
}


/********** rsa Functions *********/
  int gcd( int a, int b)
  { 
    int r;
    if(a < 0)
     a = -a;

    if(b < 0) 
    b = -b;

    if(b == 0)
    return a;
    r = a mod b;
    // exhange r and b, initialize a = b and b = r;
    a = b;
    b = r;
    return gcd(a,b);
  }

  void extended_euclid(int A1, int A2, int A3, int B1, int B2, int B3)
  {
    int Q;
    int T1,T2,T3;
    if(B3 == 0)
    {
      gcd_value = A3;
      mul_inverse = NOT_EXIST;
      return;
    }
    if(B3 == 1)
    {
      gcd_value = B3;
      mul_inverse = B2;
      return;
    }
    Q = (int)(A3/B3);
    T1 = A1 - Q*B1;
    T2 = A2 - Q*B2;
    T3 = A3 - Q*B3;
    A1 = B1;
    A2 = B2;
    A3 = B3;
    B1 = T1;
    B2 = T2;
    B3 = T3;
    extended_euclid(A1,A2,A3,B1,B2,B3);
  }

  boolean MillerRobinTest(long int n, int iteration)
  {
    // n is the given integer and k is the given desired
    // number of iterations in this primality test algorithm.
    // Return true if all the iterations test passed to give
    // the higher confidence that n is a prime, otherwise
    // return false if n is composite.
    long int m, t;
    int i,j;
    long int a, u;
    int flag;
    if(n mod 2==0)
      return false;
      // n is composite.
    m = (n-1) div 2;
    t = 1;
    while( m mod 2 == 0)
    // repeat until m is even
    {
      m = m div 2;
      t = t + 1;
    }

    for(j=0; j < iteration; j++) {
    // Repeat the test for MAX_ITERATION times
    flag = 0;
    srand((unsigned int) time(NULL));
    a = random() mod n + 1;
    // select a in {1,2,......,n}
    u = ModPower(a,m,n);
    if(u == 1 || u == n -1)
      flag =1;
    for(i=0;i<t;i++)
    {
      if(u == n -1)
        flag =1;
        u = (u * u) mod n;
    }
      if( flag ==0)
      return false;
    // n is composite
    }
      return true;
    // n is prime.
  }
  // end of MillerRobinTest().
  //KEY GENERATION ALGORITHM IN RSA CRYPTOSYSTEM.
  int KeyGeneration(key *pub_key, key *pvt_key)
  {
    long int p,q;
    long int n;
    long int phi_n;
    long int e;
    // Select p and q which are primes and p<q.
    
    while(1){
      srand((unsigned int) time(NULL));
      p = random() % LARGE;
      /* test for even number */
      if( (p & 0x01) == 0)
        continue;
      if(MillerRobinTest(p, MAX_ITERATION))
        break;
    }

      while(1)
      {
        srand((unsigned int) time(NULL));
        q=random() % LARGE;
        if( q == p)
        {
          srand((unsigned int) time(NULL));
          q = random() % LARGE;
          continue;
        }

        if(MillerRobinTest(q, MAX_ITERATION))
          break;
      }
      // Compute n.

      if((p*q) < 6800){
        printf("\nInsufficient value of n : %ld , Regenerating keys\n", (p*q));
        return 0;
      }

      if(verify_prime(p) && verify_prime(q) )
        printf("p =%ld, q =%ld are primes\n", p, q);
      else{
        printf("p =%ld, q =%ld are composite, hence ignored and regenerated\n", p, q);
        return 0;
      }

      printf("p =%ld, q =%ld\n", p, q);
      n = p * q;

      // Compute Euler's phi(totient) function
      phi_n = (p-1)*(q-1);
      // Compute e such that gcd(e,phi_n(n))=1.
    
      while(1)
      {
        e = random()%phi_n;
        if(gcd(e, phi_n)==1)
        break;
      }
      // Compute d such that ed=1(mod phi_n(n)).
  
      extended_euclid(1,0, phi_n,0,1, e);

      if(mul_inverse <0) {
        mul_inverse = -mul_inverse;
        mul_inverse = ((phi_n -1) * mul_inverse) mod phi_n;
      }
            // Put Public Key and Private Key.
          pub_key->public_key.n = n;
          pub_key->public_key.e = e;
          pvt_key->private_key.n = n;
          pvt_key->private_key.d = mul_inverse;

    return 1;
  }
  // end of KeyGeneraion()

  boolean verify_prime(long int p)
  {
      long int d;
      // Test for p;
      for(d =2; d <= (long int) sqrt(p); d++ )
        if( p % d ==0)
          return false;
        return true;
    }

  // Decryption Algorithm(D)
  long int DecryptionAlgorithm(long int C, key pvt_key)
  {
    // Bob retrieves M as M := C^d(mod n)
    long int M;
    
      //printf("\nDecryption keys= (%ld,%ld)\n\r",pvt_key.private_key.n,pvt_key.private_key.d);
      M = ModPower(C, pvt_key.private_key.d, pvt_key.private_key.n);
    return M;
  }


  // Algorithm: Modular Power: x^e(mod n).
  
// end of ModPower().


/*** End of client.c ***/

