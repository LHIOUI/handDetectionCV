#include "opencv2/imgproc/imgproc.hpp"
#include "opencv2/imgproc/types_c.h"
#include "opencv2/highgui/highgui_c.h"
#include <opencv2/opencv.hpp>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <string>
#include "myImage.hpp"
#include "roi.hpp"
#include "handGesture.hpp"
#include <vector>
#include <cmath>
#include "main.hpp"

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

//Serial communication stuff
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <fcntl.h>

// SSH stuff
#include <cstdlib>
#include <libssh/libssh.h>
#include <errno.h>

using namespace cv;
using namespace std;

/* Global Variables  */
int fontFace = FONT_HERSHEY_PLAIN;
int square_len;
int avgColor[NSAMPLES][3] ;
int c_lower[NSAMPLES][3];
int c_upper[NSAMPLES][3];
int avgBGR[3];
int nrOfDefects;
int iSinceKFInit;
struct dim{int w; int h;}boundingDim;
    VideoWriter out;
Mat edges;
My_ROI roi1, roi2,roi3,roi4,roi5,roi6;
vector <My_ROI> roi;
vector <KalmanFilter> kf;
vector <Mat_<float> > measurement;

vector <double> found_areas;

int serialPort; // File descriptor for serial port

// SSH stuff
ssh_session session;
ssh_channel channel;

int verify_knownhost(ssh_session session)
{
	int state, hlen;
	unsigned char *hash = NULL;
	char *hexa;
	char buf[10];

	state = ssh_is_server_known(session);
	hlen = ssh_get_pubkey_hash(session, &hash);

	if (hlen < 0)
		return -1;

	switch (state)
	{
		case SSH_SERVER_KNOWN_OK:
			break; /* ok */

		case SSH_SERVER_KNOWN_CHANGED:
			fprintf(stderr, "Host key for server changed: it is now:\n");
			ssh_print_hexa("Public key hash", hash, hlen);
			fprintf(stderr, "For security reasons, connection will be stopped\n");
			free(hash);
			return -1;

		case SSH_SERVER_FOUND_OTHER:
			fprintf(stderr, "The host key for this server was not found but an other"
			"type of key exists.\n");
			fprintf(stderr, "An attacker might change the default server key to"
			"confuse your client into thinking the key does not exist\n");
			free(hash);
			return -1;

		case SSH_SERVER_FILE_NOT_FOUND:
			fprintf(stderr, "Could not find known host file.\n");
			fprintf(stderr, "If you accept the host key here, the file will be"
			"automatically created.\n");
			/* fallback to SSH_SERVER_NOT_KNOWN behavior */

		case SSH_SERVER_NOT_KNOWN:
			hexa = ssh_get_hexa(hash, hlen);
			fprintf(stderr,"The server is unknown. Do you trust the host key?\n");
			fprintf(stderr, "Public key hash: %s\n", hexa);
			free(hexa);
			if (fgets(buf, sizeof(buf), stdin) == NULL)
			{
				free(hash);
				return -1;
			}
			if (strncasecmp(buf, "yes", 3) != 0)
			{
				free(hash);
				return -1;
			}
			if (ssh_write_knownhost(session) < 0)
			{
				fprintf(stderr, "Error %s\n", strerror(errno));
				free(hash);
				return -1;
			}
			break;

		case SSH_SERVER_ERROR:
			fprintf(stderr, "Error %s", ssh_get_error(session));
			free(hash);
			return -1;
	}
	free(hash);
	return 0;
}


void key_auth(){
	int rc;
	ssh_key pubkey;
	ssh_key privkey;

	rc = ssh_pki_import_pubkey_file(PUBKEY_FILE, &pubkey);
	if (rc != SSH_OK){
		cout << "Could not retrieve the public key" << endl;
		exit(-1);
	}

	rc = ssh_userauth_try_publickey(session, NULL, pubkey);
	if (rc != SSH_AUTH_SUCCESS){
		cout << "Could not pass the pubkey to the server" << endl;
		exit(-1);
	}

	rc = ssh_pki_import_privkey_file(PRIVKEY_FILE, NULL, NULL, NULL, &privkey);
	if (rc != SSH_OK){
		cout << "Could not retrieve the private key" << endl;
		exit(-1);
	}

	rc = ssh_userauth_publickey(session, NULL, privkey);
	if (rc != SSH_AUTH_SUCCESS){
		cout << "Could not authenticate to the server" << endl;
		exit(-1);
	}
}

void pass_auth(){
	int rc;

	rc = ssh_userauth_password(session, NULL, PASSWORD);
	if (rc != SSH_AUTH_SUCCESS){
		fprintf(stderr, "Error authenticating with password: %s\n",
				ssh_get_error(session));
		ssh_disconnect(session);
		ssh_free(session);
		exit(-1);
	}
}

void init_ssh(){
	session = ssh_new();
	int verbosity = SSH_LOG_PROTOCOL;
	int port = 22;
	int rc;

	if (session == NULL){
		cout << "Could not create SSH session" << endl;
		exit(-1);
	}

	ssh_options_set(session, SSH_OPTIONS_USER, USERNAME);
	ssh_options_set(session, SSH_OPTIONS_HOST, HOSTNAME);
	ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
	ssh_options_set(session, SSH_OPTIONS_PORT, &port);

	rc = ssh_connect(session);
	if (rc != SSH_OK){
		cout << "Connection failed" << endl;
		ssh_free(session);
		exit(-1);
	}

	if (verify_knownhost(session) < 0){
		cout << "Host could not be verified" << endl;
		ssh_disconnect(session);
		ssh_free(session);
		exit(-1);
	}

	// Use one of these two
	//key_auth();
	pass_auth();
}

void init_channel(){
	int rc;

	channel = ssh_channel_new(session);
	if (channel == NULL)
		return SSH_ERROR;

	rc = ssh_channel_open_session(channel);
	if (rc != SSH_OK){
		cout << "Opening session failed" << endl;
		ssh_channel_free(channel);
		exit(-1);
	}

}

void exec_ssh(char* cmd){
	int rc;
	unsigned int nbytes;
	char buffer[256];

	init_channel();

	/* Example
	rc = ssh_channel_request_exec(channel, "echo \"22\" > /dev/null; echo $?");
	*/
	rc = ssh_channel_request_exec(channel, cmd);
	if (rc != SSH_OK){
		cout << "Executing command failed" << endl;
		exit(-1);
	}

	nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);

	// Write the response to stdout
	//fwrite(buffer, 1, nbytes, stdout);

	ssh_channel_send_eof(channel);
	ssh_channel_close(channel);
	ssh_channel_free(channel);
}

void close_ssh(){
	ssh_disconnect(session);
	ssh_free(session);
}

void initSerialCommunication()
{
    struct termios portOptions; // struct to hold the port settings
    serialPort = open(SERIAL_PORT_NAME, O_RDWR | O_NOCTTY | O_NDELAY );

    DIE(serialPort < 0, "openining of serial interface failed");
    
    // Fetch the current port settings
    tcgetattr(serialPort, &portOptions);
    
    // Flush the port's buffers (in and out) before we start using it
    tcflush(serialPort, TCIOFLUSH);

    // Set the input and output baud rates
    cfsetispeed(&portOptions, B115200);
    cfsetospeed(&portOptions, B115200);

    // c_cflag contains a few important things- CLOCAL and CREAD, to prevent
    //   this program from "owning" the port and to enable receipt of data.
    //   Also, it holds the settings for number of data bits, parity, stop bits,
    //   and hardware flow control. 
    portOptions.c_cflag |= CLOCAL;
    portOptions.c_cflag |= CREAD;
    // Set up the frame information.
    portOptions.c_cflag &= ~CSIZE; // clear frame size info
    portOptions.c_cflag |= CS8;    // 8 bit frames
    portOptions.c_cflag &= ~PARENB;// no parity
    portOptions.c_cflag &= ~CSTOPB;// one stop bit

    // Now that we've populated our options structure, let's push it back to the
    //   system.
    tcsetattr(serialPort, TCSANOW, &portOptions);

    // Flush the buffer one more time.
    tcflush(serialPort, TCIOFLUSH);

}

void closeSerial()
{
    int rc;
    rc = close(serialPort);
    DIE(rc < 0, "close() of serial interface failed");
}

void writeSerial(const char* buffer)
{
    int rc;
    /*initSerialCommunication();
    rc = write(serialPort, buffer, strlen(buffer));
    DIE(rc < 0, "writeSerial() failed");
    closeSerial();*/

    string command;
    int status;
    command = string(buffer);
    command = "\"echo '" + command + "' > " + SERIAL_PORT_NAME + "\"";

    char *cmd[] = {
        "",
        NULL
    };
    cmd[0] = (char *) calloc(100, sizeof(char));
    strcpy(cmd[0], command.c_str());

    //fork exec alternative
    pid_t pid = fork();
    switch (pid) {
    case -1:
        /* error forking */
        cout << "Fork failed" << endl;
        return;
    case 0:
        /* child process */
        execvp(cmd[0], cmd);
 
    default:
        /* parent process */
        break;
    }
 
    /* only parent process gets here */
    waitpid(pid, &status, 0);
    if (WIFEXITED(status))
        printf("Child %d terminated normally, with code %d\n",
            pid, WEXITSTATUS(status));

}

/* end global variables */

void init(MyImage *m){
    square_len=20;
    iSinceKFInit=0;
}

// change a color from one space to another
void col2origCol(int hsv[3], int bgr[3], Mat src){
    Mat avgBGRMat=src.clone();  
    for(int i=0;i<3;i++){
        avgBGRMat.data[i]=hsv[i];   
    }
    cvtColor(avgBGRMat,avgBGRMat,COL2ORIGCOL);
    for(int i=0;i<3;i++){
        bgr[i]=avgBGRMat.data[i];   
    }
}

void printText(Mat src, string text){
    int fontFace = FONT_HERSHEY_PLAIN;
    putText(src,text,Point(src.cols/2, src.rows/10),fontFace, 1.2f,Scalar(200,0,0),2);
}

void waitForPalmCover(MyImage* m){

    m->cap >> m->src;

    GaussianBlur(m->src,m->src,Size(3,3),0,1); //apply some smoothing before
    blur(m->src,m->src,Size(3,3));
    
    //see: http://docs.opencv.org/modules/photo/doc/denoising.html
    fastNlMeansDenoisingColored(m->src,m->src,5);
    
    //If normalize is used, then only palm should be detected, without fingers (TODO:?)
    //normalize(m->src,m->src,0,255,NORM_MINMAX,-1);
    
    flip(m->src,m->src,1);
    roi.push_back(My_ROI(Point(m->src.cols/3, m->src.rows/6),Point(m->src.cols/3+square_len,m->src.rows/6+square_len),m->src));
    roi.push_back(My_ROI(Point(m->src.cols/4, m->src.rows/2),Point(m->src.cols/4+square_len,m->src.rows/2+square_len),m->src));
    roi.push_back(My_ROI(Point(m->src.cols/3, m->src.rows/1.5),Point(m->src.cols/3+square_len,m->src.rows/1.5+square_len),m->src));
    roi.push_back(My_ROI(Point(m->src.cols/2, m->src.rows/2),Point(m->src.cols/2+square_len,m->src.rows/2+square_len),m->src));
    roi.push_back(My_ROI(Point(m->src.cols/2.5, m->src.rows/2.5),Point(m->src.cols/2.5+square_len,m->src.rows/2.5+square_len),m->src));
    roi.push_back(My_ROI(Point(m->src.cols/2, m->src.rows/1.5),Point(m->src.cols/2+square_len,m->src.rows/1.5+square_len),m->src));
    roi.push_back(My_ROI(Point(m->src.cols/2.5, m->src.rows/1.8),Point(m->src.cols/2.5+square_len,m->src.rows/1.8+square_len),m->src));

    for(int i =0;i<50;i++){
        m->cap >> m->src;
        flip(m->src,m->src,1);
        blur(m->src,m->src,Size(3,3));
        //fastNlMeansDenoisingColored(m->src,m->src,3);
        for(int j=0;j<NSAMPLES;j++){
            roi[j].draw_rectangle(m->src);
        }
        string imgText=string("Cover rectangles with palm");
        printText(m->src,imgText);  
        
        if(i==30){
            #ifdef VERBOSE_JPG
                imwrite("./images/waitforpalm1.jpg",m->src);
            #endif
        }

        #ifdef DEBUG_WINDOW
            imshow("img1", m->src);
        #endif

        out << m->src;
        if(cv::waitKey(30) >= 0) break;
    }
}

int getMedian(vector<int> val){
  int median;
  size_t size = val.size();
  sort(val.begin(), val.end());
  if (size  % 2 == 0)  {
      median = val[size / 2 - 1] ;
  } else{
      median = val[size / 2];
  }
  return median;
}


void getAvgColor(MyImage *m,My_ROI roi,int avg[3]){
    Mat r;
    roi.roi_ptr.copyTo(r);
    vector<int>hm;
    vector<int>sm;
    vector<int>lm;
    // generate vectors
    for(int i=2; i<r.rows-2; i++){
        for(int j=2; j<r.cols-2; j++){
            hm.push_back(r.data[r.channels()*(r.cols*i + j) + 0]) ;
            sm.push_back(r.data[r.channels()*(r.cols*i + j) + 1]) ;
            lm.push_back(r.data[r.channels()*(r.cols*i + j) + 2]) ;
        }
    }
    avg[0]=getMedian(hm);
    avg[1]=getMedian(sm);
    avg[2]=getMedian(lm);
}

void average(MyImage *m){
    m->cap >> m->src;
    flip(m->src,m->src,1);
    for(int i=0;i<30;i++){
        m->cap >> m->src;
        flip(m->src,m->src,1);
        cvtColor(m->src,m->src,ORIGCOL2COL);
        for(int j=0;j<NSAMPLES;j++){
            getAvgColor(m,roi[j],avgColor[j]);
            roi[j].draw_rectangle(m->src);
        }   
        cvtColor(m->src,m->src,COL2ORIGCOL);
        string imgText=string("Finding average color of hand");
        printText(m->src,imgText);

        #ifdef DEBUG_WINDOW
            imshow("img1", m->src);
        #endif

        if(cv::waitKey(30) >= 0) break;
    }
}

void initTrackbars(){
    for(int i=0;i<NSAMPLES;i++){
        c_lower[i][0]=12;
        c_upper[i][0]=7;
        c_lower[i][1]=30;
        c_upper[i][1]=40;
        c_lower[i][2]=80;
        c_upper[i][2]=80;
    }
    createTrackbar("lower1","trackbars",&c_lower[0][0],255);
    createTrackbar("lower2","trackbars",&c_lower[0][1],255);
    createTrackbar("lower3","trackbars",&c_lower[0][2],255);
    createTrackbar("upper1","trackbars",&c_upper[0][0],255);
    createTrackbar("upper2","trackbars",&c_upper[0][1],255);
    createTrackbar("upper3","trackbars",&c_upper[0][2],255);
}


void normalizeColors(MyImage * myImage){
    // copy all boundries read from trackbar
    // to all of the different boundries
    for(int i=1;i<NSAMPLES;i++){
        for(int j=0;j<3;j++){
            c_lower[i][j]=c_lower[0][j];    
            c_upper[i][j]=c_upper[0][j];    
        }   
    }
    // normalize all boundries so that 
    // threshold is whithin 0-255
    for(int i=0;i<NSAMPLES;i++){
        if((avgColor[i][0]-c_lower[i][0]) <0){
            c_lower[i][0] = avgColor[i][0] ;
        }if((avgColor[i][1]-c_lower[i][1]) <0){
            c_lower[i][1] = avgColor[i][1] ;
        }if((avgColor[i][2]-c_lower[i][2]) <0){
            c_lower[i][2] = avgColor[i][2] ;
        }if((avgColor[i][0]+c_upper[i][0]) >255){ 
            c_upper[i][0] = 255-avgColor[i][0] ;
        }if((avgColor[i][1]+c_upper[i][1]) >255){
            c_upper[i][1] = 255-avgColor[i][1] ;
        }if((avgColor[i][2]+c_upper[i][2]) >255){
            c_upper[i][2] = 255-avgColor[i][2] ;
        }
    }
}

void produceBinaries(MyImage *m){   
    Scalar lowerBound;
    Scalar upperBound;
    Mat foo;
    for(int i=0;i<NSAMPLES;i++){
        normalizeColors(m);
        lowerBound=Scalar( avgColor[i][0] - c_lower[i][0] , avgColor[i][1] - c_lower[i][1], avgColor[i][2] - c_lower[i][2] );
        upperBound=Scalar( avgColor[i][0] + c_upper[i][0] , avgColor[i][1] + c_upper[i][1], avgColor[i][2] + c_upper[i][2] );
        m->bwList.push_back(Mat(m->srcLR.rows,m->srcLR.cols,CV_8U));    
        inRange(m->srcLR,lowerBound,upperBound,m->bwList[i]);   
    }
    m->bwList[0].copyTo(m->bw);
    for(int i=1;i<NSAMPLES;i++){
        m->bw+=m->bwList[i];    
    }
    medianBlur(m->bw, m->bw,7);
}

void initWindows(MyImage m){
    namedWindow("trackbars",CV_WINDOW_KEEPRATIO);
    namedWindow("img1",CV_WINDOW_FULLSCREEN);
}

void showWindows(MyImage m){
    pyrDown(m.bw,m.bw);
    pyrDown(m.bw,m.bw);
    Rect roi( Point( 3*m.src.cols/4,0 ), m.bw.size());
    vector<Mat> channels;
    Mat result;
    for(int i=0;i<3;i++)
        channels.push_back(m.bw);
    merge(channels,result);
    result.copyTo( m.src(roi));
    imshow("img1",m.src);   
}

int findBiggestContour(vector<vector<Point> > contours){
    int indexOfBiggestContour = -1;
    int sizeOfBiggestContour = 0;
    for (int i = 0; i < contours.size(); i++){
        if(contours[i].size() > sizeOfBiggestContour){
            sizeOfBiggestContour = contours[i].size();
            indexOfBiggestContour = i;
        }
    }
    return indexOfBiggestContour;
}

void myDrawContours(MyImage *m,HandGesture *hg, int clear_areas){

    drawContours(m->src,hg->hullP,hg->cIdx,cv::Scalar(200,0,0),2, 8, vector<Vec4i>(), 0, Point());

    rectangle(m->src,hg->bRect.tl(),hg->bRect.br(),Scalar(0,0,200));
    vector<Vec4i>::iterator d=hg->defects[hg->cIdx].begin();
    int fontFace = FONT_HERSHEY_PLAIN;
    int found_areas_sz;
    double estimated_distance;
    double focal_distance;
    double area; 
    double delta;
    double sum_vect, avg, accum, stdev;
    double min_elem, max_elem;
    vector<double>::const_iterator i;

    
    vector<Mat> channels;
        Mat result;
        for(int i=0;i<3;i++)
            channels.push_back(m->bw);
        merge(channels,result);
        
        #ifdef DEBUG
            drawContours(result,hg->contours,hg->cIdx,cv::Scalar(0,200,0),6, 8, vector<Vec4i>(), 0, Point());
        #endif

    //Blue contour
    drawContours(result,hg->hullP,hg->cIdx,cv::Scalar(0,0,250),10, 8, vector<Vec4i>(), 0, Point());

    if(clear_areas > TRACE_HAND_AREAS) {

        found_areas_sz = found_areas.size();

        //Take a decision
        min_elem = *min_element(begin(found_areas), end(found_areas));
        max_elem = *max_element(begin(found_areas), end(found_areas));

        delta = abs(max_elem - min_elem);

        sum_vect = accumulate(begin(found_areas), end(found_areas), 0.0);
        avg = sum_vect / found_areas_sz;

        accum = inner_product(begin(found_areas), end(found_areas), begin(found_areas), 0.0); //square sum
        stdev = sqrt(accum / found_areas_sz - avg * avg);

        #ifdef DEBUG
            cout << "[ ";
            for(i = found_areas.begin(); i != found_areas.end(); i++)
                cout << *i << ", ";
            cout << " ]" << endl << endl;
        #endif

        cout << "Max: " << max_elem << " Min: " << min_elem << " Delta: " << delta;
        cout << " Mean: " << avg << " Stdev: " << stdev << endl;
        fflush(stdout);

        if(stdev > STD_TRESH) {
            if(delta >= SOFT_GRAB_D && 
                delta <= SOFT_GRAB_D + 5000 
                ) {
                //writeSerial - TODO, only if stdev > STD_TRESH
                cout << "Decision sent to serial: SOFT_GRAB: " << SOFT_GRAB << endl;
            }

            if(delta > SOFT_GRAB_D + 5000 && 
                delta <= GRAB_D + 5000 
                ) {
                //writeSerial - TODO, only if stdev > STD_TRESH
                cout << "Decision sent to serial: GRAB: " << GRAB << endl;
            }

            if(delta > GRAB_D + 5000 && 
                delta <= OPEN_D
                ) {

                //Take the average area+stdev in account to determine if it is
                //OPEN or STRONG GRAB
                if(avg <= STRONG_GRAB_A) {
                    cout << "Decision sent to serial: STRONG_GRAB_D: " << STRONG_GRAB << endl;
                    //writeSerial - TODO, only if stdev > STD_TRESH
                } else {
                    cout << "Decision sent to serial: OPEN: " << OPEN << endl;
                }
            }
        } else 
        //Some with stdev < STD_TRESH, a static position, which the robotic hand should
        //change accordingly
        if(stdev < STD_TRESH) {
            if(OPEN_A - VICINITY < avg && avg < OPEN_A + VICINITY)
                cout << "Decision sent to serial: OPEN: " << OPEN << endl;

            if(STRONG_GRAB_A - VICINITY < avg && avg < STRONG_GRAB_A + VICINITY)
                cout << "Decision sent to serial: STRONG_GRAB_A: " << STRONG_GRAB << endl;

            if(GRAB_A - VICINITY < avg && avg < GRAB_A + VICINITY)
                cout << "Decision sent to serial: GRAB: " << GRAB << endl;

            if(SOFT_GRAB_A - VICINITY < avg && avg < SOFT_GRAB_A + VICINITY)
                cout << "Decision sent to serial: SOFT_GRAB: " << SOFT_GRAB << endl;

            if(avg < SOFT_GRAB_A - VICINITY)
                cout << "Decision sent to serial: CLOSE: " << CLOSE << endl;
        }


        // if(delta >= SOFT_GRAB_D && delta <= SOFT_GRAB_D + 10000) {
        //     cout << "Decision sent to serial: SOFT_GRAB: " << SOFT_GRAB << endl;
        //     //writeSerial - TODO
        // } else if (delta > SOFT_GRAB_D + 10000 && delta <= STRONG_GRAB_D){
        //     cout << "Decision sent to serial: STRONG_GRAB: " << STRONG_GRAB << endl;
        //     //writeSerial - TODO
        // } else if (delta > STRONG_GRAB_D) {
        //     cout << "Decision sent to serial: OPEN: " << OPEN << endl;
        // }

        found_areas.clear();
    }

    //Get moments to compute area
    if( !hg->hullP.empty() ) {
        int i; 

        for(i=0;i<hg->hullP.size();i++) {
            if(!hg->hullP[i].empty()) {
                area = contourArea(hg->hullP[i]);
                //cout << " Area: " << area << endl;  
                //focal_distance = area * Z_PLACE_HAND / D_GRAB_DIAMETER;
                //estimated_distance = D_GRAB_DIAMETER * focal_distance / area;
                //cout << "Estimated distance (in pixels or cm?) " << estimated_distance << endl;
                found_areas.push_back(area);

            }                
        }
    }

    while( d!=hg->defects[hg->cIdx].end() ) {
        Vec4i& v=(*d);
        int startidx=v[0]; Point ptStart(hg->contours[hg->cIdx][startidx] );
        int endidx=v[1]; Point ptEnd(hg->contours[hg->cIdx][endidx] );
        int faridx=v[2]; Point ptFar(hg->contours[hg->cIdx][faridx] );
        float depth = v[3] / 256;
    
        #ifdef DEBUG
            line( m->src, ptStart, ptFar, Scalar(0,255,0), 1 );
            line( m->src, ptEnd, ptFar, Scalar(0,255,0), 1 );
            circle( m->src, ptFar,   4, Scalar(0,255,0), 2 );
            circle( m->src, ptEnd,   4, Scalar(0,0,255), 2 );
            circle( m->src, ptStart,   4, Scalar(255,0,0), 2 );
        #endif
        circle( result, ptFar,   9, Scalar(0,205,0), 5 );
        
        d++;

     }
    #ifdef VERBOSE_JPG
        imwrite("./images/contour_defects_before_eliminate.jpg",result);
    #endif
}


void makeContours(MyImage *m, HandGesture* hg, int clear_areas){
    Mat aBw;
    pyrUp(m->bw,m->bw);
    m->bw.copyTo(aBw);
    findContours(aBw,hg->contours,CV_RETR_EXTERNAL,CV_CHAIN_APPROX_NONE);
    hg->initVectors(); 
    hg->cIdx=findBiggestContour(hg->contours);
    if(hg->cIdx!=-1){
//      approxPolyDP( Mat(hg->contours[hg->cIdx]), hg->contours[hg->cIdx], 11, true );
        hg->bRect=boundingRect(Mat(hg->contours[hg->cIdx]));        
        convexHull(Mat(hg->contours[hg->cIdx]),hg->hullP[hg->cIdx],false,true);
        convexHull(Mat(hg->contours[hg->cIdx]),hg->hullI[hg->cIdx],false,false);
        approxPolyDP( Mat(hg->hullP[hg->cIdx]), hg->hullP[hg->cIdx], 18, true );
        if(hg->contours[hg->cIdx].size()>3 ){
            convexityDefects(hg->contours[hg->cIdx],hg->hullI[hg->cIdx],hg->defects[hg->cIdx]);
            hg->eleminateDefects(m);
        }
        bool isHand=hg->detectIfHand();
        hg->printGestureInfo(m->src);
        if(isHand){ 
            hg->getFingerTips(m);
            hg->drawFingerTips(m);
            myDrawContours(m,hg,clear_areas);
        }
    }
}


int main(){

    //writeSerial("#555552~");
    //cout << "Am scris pe seriala " << endl;

    MyImage m(CAMERA_INDEX);       
    HandGesture hg;
    init(&m);       
    m.cap >>m.src;

    #ifdef DEBUG_WINDOW
        namedWindow("img1",CV_WINDOW_KEEPRATIO);
    #endif

    #ifdef SAVE_VIDEO
        out.open("out.avi", CV_FOURCC('M', 'J', 'P', 'G'), 15, m.src.size(), true);
    #endif

    waitForPalmCover(&m);
    average(&m);
    destroyWindow("img1");

    cout << "Palm Cover initialization & detection finished" << endl;

    
    #ifdef DEBUG_WINDOW
        initWindows(m);
        initTrackbars();   
    #endif

    int clear_areas = 0;

    for(;;){

        hg.frameNumber++;
        m.cap >> m.src;
        flip(m.src,m.src,1);
        pyrDown(m.src,m.srcLR);

        //cica smoothing, vezi documentatia: http://docs.opencv.org/doc/tutorials/imgproc/gausian_median_blur_bilateral_filter/gausian_median_blur_bilateral_filter.html
        //blur(m.srcLR,m.srcLR,Size(3,3)); 
        GaussianBlur(m.srcLR,m.srcLR,Size(3,3),0,1); //--> parca mai bun, dar consuma procesare
        
        cvtColor(m.srcLR,m.srcLR,ORIGCOL2COL);
        produceBinaries(&m);

        cvtColor(m.srcLR,m.srcLR,COL2ORIGCOL);
        clear_areas++;
        makeContours(&m, &hg, clear_areas);
        if(clear_areas > TRACE_HAND_AREAS) {
            clear_areas = 0;
        }
        hg.getFingerNumber(&m);
        showWindows(m);
        out << m.src;

        #ifdef VERBOSE_JPG
            imwrite("./images/final_result.jpg",m.src);
        #endif

        if(cv::waitKey(30) == char('q')) break;
    }
    destroyAllWindows();
    out.release();
    m.cap.release();
    return 0;
}
