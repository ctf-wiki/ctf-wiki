#! /usr/bin/env python
# -*- coding: utf-8 -*-

from Crypto.Util.number import getPrime, long_to_bytes, bytes_to_long, isPrime, size
from Crypto.Cipher import DES
from libnum import gcd, invmod
from flag import get_flag
from hashlib import sha512
import signal
import random
import time

__author__ = 'Hcamael'

key = "abcdefg1"
k = 2048
e = 0x10001
signal.alarm(40)

def m_exit(n):
	print "==============Game Over!================="
	exit(n)

def get_bit(number, n_bit, dire):
	'''
	dire:
		1: left
		0: right
	'''

	if dire:
		sn = size(number)
		if sn % 8 != 0:
			sn += (8 - sn % 8)
		return number >> (sn-n_bit)
	else:
		return number & (pow(2, n_bit) - 1)

def pi_b(x, m):
	'''
	m:
		1: encrypt
		0: decrypt
	'''	
	enc = DES.new(key)
	if m:
		method = enc.encrypt
	else:
		method = enc.decrypt
	s = long_to_bytes(x)
	sp = [s[a:a+8] for a in xrange(0, len(s), 8)]
	r = ""
	for a in sp:
		r += method(a)
	return bytes_to_long(r)

def gen_key():
	while True:
		p = getPrime(k/2)
		if gcd(e, p-1) == 1:
			break
	q_t = getPrime(k/2)
	n_t = p * q_t
	t = get_bit(n_t, k/16, 1)
	y = get_bit(n_t, 5*k/8, 0)
	p4 = get_bit(p, 5*k/16, 1)
	u = pi_b(p4, 1)
	n = bytes_to_long(long_to_bytes(t) + long_to_bytes(u) + long_to_bytes(y))
	q = n / p
	if q % 2 == 0:
		q += 1
	while True:
		if isPrime(q) and gcd(e, q-1) == 1:
			break
		m = getPrime(k/16) + 1
		q ^= m
	return (p, q, e)

def verify():
	print "Proof of Work"
	with open("/dev/urandom") as f:
		prefix = f.read(5)
	print "Prefix: %s" %prefix.encode('base64')
	try:
		suffix = raw_input()
		s = suffix.decode('base64')
	except:
		exit(-1)
	r = sha512(prefix + s).hexdigest()
	if "fffffff" not in r:
		exit(-1)

def main():
	verify()
	usage = """
 **       **          **                                **********         
/**      /**         /**                               /////**///          
/**   *  /**  *****  /**  *****   ******  **********       /**      ****** 
/**  *** /** **///** /** **///** **////**//**//**//**      /**     **////**
/** **/**/**/******* /**/**  // /**   /** /** /** /**      /**    /**   /**
/**** //****/**////  /**/**   **/**   /** /** /** /**      /**    /**   /**
/**/   ///**//****** ***//***** //******  *** /** /**      /**    //****** 
//       //  ////// ///  /////   //////  ///  //  //       //      //////  

 **      **   ******  ********** ********   *******    ********     **    
/**     /**  **////**/////**/// /**/////   /**////**  **//////     ****   
/**     /** **    //     /**    /**        /**   /** /**          **//**  
/**********/**           /**    /*******   /*******  /*********  **  //** 
/**//////**/**           /**    /**////    /**///**  ////////** **********
/**     /**//**    **    /**    /**        /**  //**        /**/**//////**
/**     /** //******     /**    /**        /**   //** ******** /**     /**
//      //   //////      //     //         //     // ////////  //      // 

   ********                               
  **//////**                              
 **      //   ******   **********   ***** 
/**          //////** //**//**//** **///**
/**    *****  *******  /** /** /**/*******
//**  ////** **////**  /** /** /**/**//// 
 //******** //******** *** /** /**//******
  ////////   //////// ///  //  //  ////// 
	"""
	print usage
	print "This is a RSA Decryption System"
	print "Please enter Your team token: "
	try:
		token = raw_input()
		flag = get_flag(token)
		assert len(flag) == 38
	except:
		print "Token error!"
		m_exit(-1)

	p, q, e = gen_key()
	n = p * q
	phi_n = (p-1)*(q-1)
	d = invmod(e, phi_n)
	while True:
		e2 = random.randint(0x1000, 0x10000)
		if gcd(e2, phi_n) == 1:
			break
	print "n: ", hex(n)
	print "e: ", hex(e)
	print "e2: ", hex(e2)
	flag = bytes_to_long(flag)
	enc_flag = pow(flag, e2, n)
	print "Your flag is: ", hex(enc_flag)
	print "============Start Games============"
	print "Please enter your cipher: "
	while True:
		try:
			s = raw_input()
			c = int(s)
		except:
			m_exit(-1)
		m = pow(c, d, n)
		print "Your Plaintext is: ", hex(m)
		time.sleep(1)

if __name__ == '__main__':
	main()
