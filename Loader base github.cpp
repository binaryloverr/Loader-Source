#include <iostream>
#include <Windows.h>
#include <cstdint>
#include <memory>
#include "prot/protector.h"
#include "spoof.h"
#include "load.h"
#include "lazy.h"
#include "dbg.h"
#include "auth/auth.hpp"
#include "prot/anti_debugger.h"

void DeleteKey(std::ifstream& File)
{

	std::string regfile("key.txt");
	std::ofstream(regfile, std::ios::trunc);
	File.setstate(std::ios::failbit);
	remove(regfile.c_str());
}

HWND windowid = NULL;

inline std::string სახელი = ( _xor_( " "  ) ); //name
inline std::string მესაკუთრე = ( _xor_ ( " " ) ); //ownerid
inline std::string საიდუმლო = ( _xor_ ( " " ) ); //secret
inline std::string ვერსია = ( _xor_ ( "1.0" ) );
inline std::string ბმული = ( _xor_ ( "https://keyauth.win/api/1.2/" ) );
inline KeyAuth::api აპლიკაცია ( სახელი, მესაკუთრე, საიდუმლო, ვერსია, ბმული );

std::string readFileIntoString(const std::string& path) {
	

	auto ss = std::ostringstream{};
	std::ifstream input_file(path);
	if (!input_file.is_open()) {
		std::cerr << ("Could Not Open License Key File") << std::endl;
		exit(EXIT_FAILURE);
	}
	ss << input_file.rdbuf();
	return ss.str();
}

std::string tm_to_readable_time2(tm ctx) {
	

	std::time_t now = std::time(nullptr);
	std::time_t expiry = std::mktime(&ctx);

	double remainingSeconds = std::difftime(expiry, now);

	if (remainingSeconds >= 60 * 60 * 24) {
		int remainingDays = static_cast<int>(remainingSeconds / (60 * 60 * 24));
		return std::to_string(remainingDays) + " day(s).";
	}
	else if (remainingSeconds >= 60 * 60) {
		int remainingHours = static_cast<int>(remainingSeconds / (60 * 60));
		return std::to_string(remainingHours) + " hour(s).";
	}
	else {
		int remainingMinutes = static_cast<int>(remainingSeconds / 60);
		return std::to_string(remainingMinutes) + " minute(s).";
	}
}


static std::time_t string_to_timet(std::string timestamp) {
	

	auto cv = strtol(timestamp.c_str(), NULL, 10); // long

	return (time_t)cv;
}

static std::tm timet_to_tm(time_t timestamp) {
	

	std::tm context;

	localtime_s(&context, &timestamp);

	return context;
}
void sleepMilliseconds(int ms) {
	std::this_thread::sleep_for(std::chrono::milliseconds(ms));
}

int main( )
{
    printf( "\n Loader Github base made by tlhelp32" );

    Sleep (1000 );

	system( skCrypt( "cls" ) );

    LI_FN( SetConsoleTextAttribute )( GetStdHandle( STD_OUTPUT_HANDLE ), 0x5 );

    std::thread(security_loop).detach( );

    LI_FN (SetConsoleTitleA ) ( skCrypt( ( "Loader Base") ) );

	dbg->Anti_Debug( );

	antii->antidbg( );

	აპლიკაცია.init( );

	LI_FN( system ) ( skCrypt ( "cls" ) );

	LI_FN( printf ) ( skCrypt ( "\n \033[0m[\033[1;31m~\033[0m]" ) );

	std::cout << ( skCrypt ( " Connecting To Servers" ) ) << std::flush;

	int dots = 0;

	აპლიკაცია.init( );

	std::random_device rd;

	std::mt19937 gen(rd( ) );

	std::uniform_int_distribution<int> randomDelay( 5000, 10000 );

	int duration = randomDelay( gen );

	while ( duration > 0 ) {
		sleepMilliseconds( 900 );
		std::cout << skCrypt( "." ) << std::flush;
		dots++;
		duration -= 900;


		if ( dots == 10 || duration <= 0 ) {
			std::cout << std::endl;
			dots = 0;
		}
	}
	LI_FN( system ) ( skCrypt ( "cls" ) );

	LI_FN( Sleep ) (500 );

	LI_FN( printf ) ( skCrypt ( "\n \033[0m[\033[1;31m+\033[0m]" ) );

	აპლიკაცია.init( );

	std::cout << ( skCrypt( " Done." ) ) << std::flush;

	LI_FN( Sleep ) ( 1000 );

	LI_FN( system ) ( skCrypt ( "cls" ) );

	LI_FN( printf ) ( skCrypt ( "\n \033[0m[\033[1;31m&\033[0m]" ) );

	std::cout << ( skCrypt ( " Loading Login Dashboard" ) ) << std::flush;

	int dots1 = 0;

	აპლიკაცია.init( );

	std::random_device rd1;

	std::mt19937 gen1 ( rd1 ( ) );

	std::uniform_int_distribution<int> randomDelay1( 2500, 4000 );

	int duration1 = randomDelay1( gen1 );


	while ( duration1 > 0 ) {
		sleepMilliseconds ( 900 );
		std::cout << skCrypt( "." ) << std::flush;
		dots1++;
		duration1 -= 900;


		if ( dots1 == 10 || duration1 <= 0 ) {
			std::cout << std::endl;
			dots1 = 0;
		}
	}

	LI_FN( system ) (skCrypt ( "cls" ) );

	LI_FN( Sleep )( 500 );

	LI_FN( printf ) ( skCrypt( "\n \033[0m[\033[1;31m+\033[0m]" ) );

	აპლიკაცია.init( );

	std::cout << ( skCrypt(" Done." ) ) << std::flush;

	LI_FN( Sleep ) ( 1000 );

	LI_FN( system ) ( skCrypt("cls" ) );

	LI_FN( printf ) (skCrypt( "\n \033[0m[\033[1;31m=\033[0m]" ) );

	std::cout << ( " Enter Your License Key: " );  

	აპლიკაცია.init( );

	std::string key;

	std::cin >> key;
	აპლიკაცია.license( key );
	LI_FN( Sleep )( 2000 );

	LI_FN( system ) ( skCrypt( "cls" ) );
	LI_FN( printf ) ( skCrypt( "\n \033[0m[\033[1;31m~\033[0m]" ) );

	std::cout << ( skCrypt ( " Fecthing Product Info" ) ) << std::flush;
	int dots2 = 0;
	std::random_device rd2;
	std::mt19937 gen2( rd2 ( ) );
	std::uniform_int_distribution<int> randomDelay2( 1500, 3000 );
	int duration2 = randomDelay2( gen2 );

	while ( duration2 > 0 ) {
		sleepMilliseconds( 900 );
		std::cout << skCrypt( "." ) << std::flush;
		dots2++;
		duration2 -= 900;

		if ( dots2 == 10 || duration2 <= 0 ) {
			std::cout << std::endl;
			dots2 = 0;
		}
	}

	LI_FN( system ) ( skCrypt ( "cls" ) );

	LI_FN( Sleep )( 500) ;
	აპლიკაცია.init( );
	LI_FN( printf )( skCrypt( "\n \033[0m[\033[1;31m+\033[0m]" ) );

	std::cout << ( skCrypt ( " Done." ) ) << std::flush;

	LI_FN( Sleep ) ( 1000 );
	აპლიკაცია.init( );
	LI_FN( system ) ( skCrypt ( "cls" ) );

	LI_FN (SetConsoleTitleA ) ( ( skCrypt ( "" ) ) );
	LI_FN( system ) ( skCrypt ( "cls"));

	LI_FN( system) (skCrypt( "cls" ) );
	LI_FN( Sleep ) ( 100 );

	LI_FN( system ) ( skCrypt ( "cls" ) );
	LI_FN( printf ) ( skCrypt ( "\n \033[0m[\033[1;31m$\033[0m]" ) );
	აპლიკაცია.init( );
	std::cout << ( skCrypt( " Downloading Dependencies" ) ) << std::flush;
	int dots3 = 0;

	std::random_device rd3;
	std::mt19937 gen3( rd3( ) );
	std::uniform_int_distribution<int> randomDelay3( 1500, 3000 );
	int duration3 = randomDelay3(gen3);

	while ( duration3 > 0 ) {
		sleepMilliseconds( 900 );
		std::cout << skCrypt( "." ) << std::flush;
		dots3++;
		duration3 -= 900;


		if (dots3 == 10 || duration3 <= 0) {
			std::cout << std::endl;
			dots3 = 0;
		}
	}

	LI_FN( system ) ( skCrypt( "cls" ) );

	LI_FN( Sleep ) ( 500 );

	LI_FN( printf ) (skCrypt( "\n \033[0m[\033[1;31m+\033[0m]" ) );
	აპლიკაცია.init( );
	std::cout << ( skCrypt( " Done Downloading." ) ) << std::flush;

	LI_FN( Sleep ) ( 1000 );

	LI_FN( system ) ( skCrypt ( "cls" ) );

    if ( !load->spfdrv ( ) )
    {
        printf( skCrypt ( "\n {error 1}  Couldnt Download Dependencies. Contact support." ) );
		LI_FN( Sleep ) ( 1000);
		LI_FN( system ) ( skCrypt ( "cls" ) );
    }
    else
    {
        printf( "\n Successfully Downloaded Dependencies." );
		LI_FN( Sleep ) ( 1000 );
		LI_FN( system ) ( skCrypt ( "cls" ) );
    }

	აპლიკაცია.init( );

    if (! cheatdrv->cheat ( ) )
    {
        printf( skCrypt ( "\n {error 2}  Couldnt Download Dependencies. Contact support." ) );
		LI_FN( Sleep ) ( 1000);
		LI_FN( system ) ( skCrypt( "cls" ) );
    }
    else
    {
        printf( skCrypt ( "\n Successfully Downloaded Dependencies." ) );
        Sleep (1000 );
		LI_FN( system ) ( skCrypt( "cls" ) );
    }

	return 0;
}

