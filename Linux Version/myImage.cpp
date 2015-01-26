#include "myImage.hpp"
#include <opencv2/imgproc/imgproc.hpp>
#include<opencv2/opencv.hpp>
#include <opencv2/highgui/highgui.hpp>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <string>
#include "main.hpp"

using namespace cv;

MyImage::MyImage(){
}

MyImage::MyImage(int webCamera){
	cameraSrc=webCamera;
	cap=VideoCapture(webCamera);

	//Either 640 x 480 or 800 x 600
	cap.set(CV_CAP_PROP_FRAME_WIDTH,640);
	cap.set(CV_CAP_PROP_FRAME_HEIGHT,480);
	
	//check if camera exists
	DIE(!cap.isOpened(), "cannot open camera");

}

