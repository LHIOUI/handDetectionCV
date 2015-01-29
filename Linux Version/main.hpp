#ifndef _MAIN_HEADER_ 
#define _MAIN_HEADER_ 

#include <opencv2/imgproc/imgproc.hpp>
#include <opencv2/opencv.hpp>
#include <opencv2/highgui/highgui.hpp>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <string>


#define CAMERA_INDEX 0

#define ORIGCOL2COL CV_BGR2HLS
#define COL2ORIGCOL CV_HLS2BGR
#define NSAMPLES 7
#define PI 3.14159

//Assert if something fails
#define DIE(assertion, call_description)				\
	do {								\
		if (assertion) {					\
			fprintf(stderr, "(%s, %d): ",			\
					__FILE__, __LINE__);		\
			perror(call_description);			\
			exit(EXIT_FAILURE);				\
		}							\
	} while(0)


/* 
Serial interface ports:
    * On PCDUINO we have the device drivers /dev/ttyS{0,1,2,...,7}
    	* /dev/ttyS0 should be the debugging port
    	* /dev/ttyS1 should be the UART
    	* For serial I/O, you may need to write ‘3’ to the mode files for pins 0 and 1
    	* Source: https://learn.sparkfun.com/tutorials/programming-the-pcduino/serial-communications
	* On RaspberryPI device driver should be /dev/ttyAMA0    
*/
#define SERIAL_PORT_NAME "/dev/ttyS1" 

#define D_GRAB_DIAMETER  7 //size of grab hand (D) in cm
#define Z_PLACE_HAND	40	//distance (Z) in cm


#define TRACE_HAND_AREAS	69

//These values assume that hand is at approx 40 cm distance from the camera
#define 	GRAB 				"#555552~"
#define 	SOFT_GRAB 			"#333331~"
#define 	STRONG_GRAB			"#999994~"
#define		OPEN 				"#000000~"
#define		CLOSE 				"#777770~"

//area thresholds for deltas. should be double
#define		GRAB_D 				35000
#define		SOFT_GRAB_D			10000
#define		STRONG_GRAB_D		60000
#define		OPEN_D				70000

//area thresholds for average area. should be double
#define		GRAB_A 				45000
#define		SOFT_GRAB_A			35000
#define		STRONG_GRAB_A		75000
#define		OPEN_A				85000
#define 	VICINITY			7500

//if standard deviation is higher than this
//value then we need to write to serial, otherwise, DO NOTHING
//because hand position did not change!
#define STD_TRESH		7500

// SSH variables
#define USERNAME "vlad.traista"
#define HOSTNAME "fep.grid.pub.ro"
#define PASSWORD "ubuntu"
#define PUBKEY_FILE "/home/vlad/.ssh/id_rsa.pub"
#define PRIVKEY_FILE "/home/vlad/.ssh/id_rsa"

#endif
