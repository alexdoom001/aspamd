/* 
 * SpamAssassin message parser tests
 *
 */

#include <glib.h>
#include <errors.h>
#include <assassin.h>
#include <spam_samples.h>

sample_message_t messages[] =  {

{message_spam, 100,
"PROCESS SPAMC/1.4\r\n"
"content-length: 313\r\n"
"\r\n"
"X-KASTEST-ID: file wgt_100\r\n"
"Reply-To: \"Delores Akins\" <jeibijg@wildschoenau.com>\r\n"
"From: \"Delores Akins\" <jeibijg@wildschoenau.com>\r\n"
"To: gwallen@paco.net\r\n"
"Subject: spam\r\n"
"Date: Sun, 24 Oct 2004 12:57:57 -0800\r\n"
"MIME-Version: 1.0\r\n"
"Message-Id: <20041024200131.D8B434567@absolut.taide.net>\r\n"
"\r\n"
"spam is bad do not send it"},

{message_not_spam, 0,
"PROCESS SPAMC/1.4\r\n"
"content-length: 305\r\n"
"\r\n"
"From: emacs@emacs.org\r\n"
"To: johnsmith@yahoo.com\r\n"
"Date: Sun, 24 Oct 2004 12:57:57 -0800\r\n"
"Subject: scratch message\r\n"
"\r\n"
";; This buffer is for notes you don't want to save, and for Lisp\r\n"
";; evaluation.  If you want to create a file, visit that file with C-x\r\n"
";; C-f, then enter the text in that file's own buffer."},

{message_ping, 0,
"PING SPAMC/1.4\r\n"
"\r\n"},

{message_not_spam, 45,
 "PROCESS SPAMC/1.4\r\n"
"content-length: 4624\r\n"
"\r\n"
"Return-Path: dev_null_sample_spam@example.com\r\n"
"Delivery-Date: Mon, 22 Jan 2001 12:36:25 +0000\r\n"
"Return-Path: <dev_null_sample_spam@example.com>\r\n"
"Delivered-To: dev_null_sample_spam@netnoteinc.com\r\n"
"Received: from dogma.slashnull.org (dogma.slashnull.org [212.17.35.15])\r\n"
" by mail.netnoteinc.com (Postfix) with ESMTP id F138F114121\r\n"
" for <dev_null_sample_spam@netnoteinc.com>; Mon, 22 Jan 2001 12:36:21 +0000 (Eire)\r\n"
"Received: (from dev_null_sample_spam@localhost)\r\n"
"	by dogma.slashnull.org (8.9.3/8.9.3) id MAA17343\r\n"
"	for dev_null_sample_spam@netnoteinc.com; Mon, 22 Jan 2001 12:36:21 GMT\r\n"
"Received: from XeNT.ics.uci.edu (xent.ics.uci.edu [128.195.21.213])\r\n"
"	by dogma.slashnull.org (8.9.3/8.9.3) with ESMTP id MAA17336\r\n"
"	for <dev_null_sample_spam@jmason.org>; Mon, 22 Jan 2001 12:36:16 GMT\r\n"
"From: xl6Ety00V@fismat1.fcfm.buap.mx\r\n"
"Received: from blue.mydomain.com (blue.mydomain.com [208.184.130.52])\r\n"
"	by XeNT.ics.uci.edu (8.8.5/8.8.5) with ESMTP id EAA16254\r\n"
"	for <fork@xent.ics.uci.edu>; Mon, 22 Jan 2001 04:38:11 -0800 (PST)\r\n"
"Received: from ns.fundch.cl (unknown [200.28.105.254])\r\n"
"	by blue.mydomain.com (Postfix) with ESMTP id C32333424F\r\n"
"	for <fork@xent.com>; Sun, 21 Jan 2001 20:33:02 -0500 (EST)\r\n"
"X-Antispam: rblchk: (RSS) 3 Relayed through blacklisted site 200.28.105.254\r\n"
"Received: from y068k3017  [63.10.249.142] by ns.fundch.cl\r\n"
"  (SMTPD32-6.00) id A92614DC012A; Sun, 21 Jan 2001 22:21:26 -0400\r\n"
"DATE: 21 Jan 01 8:24:27 PM\r\n"
"Message-ID: <N1msdrbJXNPfV4wg9>\r\n"
"Subject: Home Based Business for Grownups\r\n"
"To: undisclosed-recipients: ;\r\n"
"Sender: dev_null_sample_spam@example.com\r\n"
"\r\n"
"\r\n"
"\r\n"
"			THIS ENTERPRISE IS AWESOMELY FEATURED \r\n"
"			    IN SEPTEMBER 2000 MILLIONAIRE, \r\n"
"			       AUGUST 2000 TYCOONS AND\r\n"
"			  AUGUST 2000 ENTREPRENEUR Magazine.\r\n"
"\r\n"
"====> Do you have a burning desire to change the quality of your existing life?\r\n"
"\r\n"
"====> Would you like to live the life that others only dream about?\r\n"
"\r\n"
"====> The fact is we have many people in our enterprise that earn over 50k per month \r\n"
"      from the privacy of their own home and are retiring in 2-3 years. \r\n"
"\r\n"
"====> Become Wealthy and having total freedom both personal and financial.\r\n"
"\r\n"
"READ ON! READ ON! READ ON! READ ON! READ ON! READ ON! READ ON!!!\r\n"
"\r\n"
"   How would you like to:(LEGALLY & LAWFULLY)\r\n"
"   1. KEEP MOST OF YOUR TAX DOLLARS \r\n"
"   2. Drastically reduce personal, business and capital gains taxes?\r\n"
"   3. Protect all assets from any form of seizure, liens, or judgments?\r\n"
"   4. Create a six figure income every 4 months?\r\n"
"   5. Restoring and preserving complete personal and financial privacy?\r\n"
"   6. Create and amass personal wealth, multiply it and protect it?\r\n"
"   7. Realize a 3 to 6 times greater returns on your money?\r\n"
"   8. Legally make yourself and your assets completely judgment-proof,\r\n"
"\r\n"
"   SEIZURE-PROOOOF, LIEN-PROOOOOOF, DIVORCE-PROOOOOOF, ATTORNEY-PROOOOOOF, IRS-PROOOOOOF\r\n"
"\r\n"
"	  ((((((((((((((((((((BECOME COMPLETELY INSULATED))))))))))))))))))))))))\r\n"
"\r\n"
"	 (((((((((((((((((((((((((HELP PEOPLE DO THE SAME))))))))))))))))))))))))))\r\n"
"\r\n"
"===> Are you a thinker, and a person that believes they deserve to have the best in life?\r\n"
"===> Are you capable of recognizing a once in a lifetime opportunity when\r\n"
"     it's looking right at you?\r\n"
"===> Countless others have missed their shot. Don't look back years later\r\n"
"     and wish you made the move.\r\n"
"\r\n"
"===> It's to my benefit to train you for success. \r\n"
"===> In fact, I'm so sure that I can do so,\r\n"
"     I'm willing to put my money where my mouth is! \r\n"
"===> Upon accepting you as a member on my team, I will provide you with\r\n"
"     complete Professional Training as well as FRESH inquiring LEADS to put\r\n"
"     you immediately on the road to success.\r\n"
"\r\n"
"If you are skeptical that's OK but don't let that stop you \r\n"
"from getting all the information you need.\r\n"
"\r\n"
"     DROP THE MOUSE=====>  AND CALL 800-320-9895 x2068 <======= DROP THE MOUSE AND CALL\r\n"
"************************************800-320-9895 x2068**************************************\r\n"
"\r\n"
"~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~\r\n"
"Your E-mail Address Removal/Deletion Instructions:\r\n"
"\r\n"
"We comply with proposed federal legislation regarding unsolicited\r\n"
"commercial e-mail by providing you with a method for your e-mail address \r\n"
"to be permanently removed from our database and any future mailings from \r\n"
"our company.\r\n"
"\r\n"
"To remove your address, please send an e-mail message with the word REMOVE \r\n"
"in the subject line to: maillistdrop@post.com \r\n"
"\r\n"
"If you do not type the word REMOVE in the subject line, your request to \r\n"
"be removed will not be processed. \r\n"
"~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~\r\n"},
{message_not_spam, 25,
"CHECK SPAMC/1.4\r\n"
"content-length: 974\r\n"
"\r\n"
"From: ref_3792mutating@jobssearch.co.uk\r\n"
"To: johnsmith@yahoo.com\r\n"
"Return-path: ref_3792mutating@jobssearch.co.uk\r\n"
"Delivery-date: Wed, 14 Sep 2005 15:05:07 +0100\r\n"
"X-ClientAddr: 62.94.45.238\r\n"
"Received: from eurostudio (ip-45-238.sn1.eutelia.it [62.94.45.238])\r\n"
"Message-ID: hqghumeayl.6189279543lfdxfircvs@Geoffxggbwkf.com\r\n"
"From: \"Geoff\" ref_3792mutating@jobssearch.co.uk\r\n"
"Date: Wed, 14 Sep 2005 15:47:25 +0100\r\n"
"Subject: JobSearch information letter (ref. 3792idiot)\r\n"
"MIME-Version: 1.0\r\n"
"Content-Type: text/html; charset=iso-8859-1\r\n"
"\r\n"
"Dear recipient,\r\n"
"\r\n"
"Avangar Technologies announces the beginning of a new unprecendented\r\n"
"global employment campaign.  reviser yeller winers butchery twenties\r\n"
"\r\n"
"Due to company's exploding growth Avangar is expanding business to the\r\n"
"European region.  During last employment campaign over 1500 people\r\n"
"worldwide took part in Avangar's business and more than half of them\r\n"
"are currently employed by the company. And now we are offering you one\r\n"
"more opportunity to earn extra money working with Avangar\r\n"
"Technologies.  druggists blame classy gentry Aladdin\r\n"
"\r\n"
"We are looking for honest, responsible, hard-working people that can\r\n"
"dedicate 2-4 hours of their time per day and earn extra Â£300-500\r\n"
"weekly. All offered positions are currently part-time and give you a\r\n"
"chance to work mainly from home.  lovelies hockey Malton meager\r\n"
"reordered\r\n"
"\r\n"
"Please visit Avangar's corporate web site\r\n"
"(http://www.avangar.com/sta/home/0077.htm) for more details regarding\r\n"
 "these vacancies.\r\n"},

{message_spam, 100,
 "CHECK SPAMC/1.4\r\n"
 "content-length: 827\r\n"
 "\r\n"
 "Subject: Test spam mail (GTUBE)\r\n"
 "Message-ID: <GTUBE1.1010101@example.net>\r\n"
 "Date: Wed, 23 Jul 2003 23:30:00 +0200\r\n"
 "From: Sender <sender@example.net>\r\n"
 "To: Recipient <recipient@example.net>\r\n"
 "Precedence: junk\r\n"
 "MIME-Version: 1.0\r\n"
 "Content-Type: text/plain; charset=us-ascii\r\n"
 "Content-Transfer-Encoding: 7bit\r\n"
 "\r\n"
 "This is the GTUBE, the\r\n"
 "  Generic\r\n"
 "  Test for\r\n"
 "  Unsolicited\r\n"
 "  Bulk\r\n"
 "  Email\r\n"
 "\r\n"
 "If your spam filter supports it, the GTUBE provides a test by which you\r\n"
 "can verify that the filter is installed correctly and is detecting incoming\r\n"
 "spam. You can send yourself a test mail containing the following string\r\n"
 "of characters (in upper case and with no white spaces and line breaks):\r\n"
 "\r\n"
 "XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X\r\n"
 "\r\n"
 "You should send this test mail from an account outside of your network.\r\n"},

{0, 0, NULL}};

sample_message_t buggy_messages[] =  {

{message_error_no_reply, 0, 
 "PROCESS SPAMC/1.4\r\n"
 "user: very_long_header_very_long_header_very_long_header_very_long_header"
 "very_long_header_very_long_header_very_long_header_very_long_header_very_long_header"
 "very_long_header_very_long_header_very_long_header_very_long_header_very_long_header"
 "very_long_header_very_long_header_very_long_header_very_long_header_very_long_header"
 "very_long_header_very_long_header_very_long_header_very_long_header_very_long_header\r\n"
 "content-length: 22\r\n"
 "\r\n"
 "Will not be reached\r\n"},

{message_error, 0,
"PING SPAMC/1.3\r\n"
"\r\n"},

{message_error, 0,
"UNKNOWN_COMMAND SPAMC/1.4\r\n"
"\r\n"},

{message_error, 0,
"PROCESS SPAMC/1.4\r\n"
"\r\n"
"X-KASTEST-ID: file wgt_100\r\n"
"Reply-To: \"Delores Akins\" <jeibijg@wildschoenau.com>\r\n"
"From: \"Delores Akins\" <jeibijg@wildschoenau.com>\r\n"
"To: gwallen@paco.net\r\n"
"Subject: spam\r\n"
"Date: Sun, 24 Oct 2004 12:57:57 -0800\r\n"
"MIME-Version: 1.0\r\n"
"Message-Id: <20041024200131.D8B434567@absolut.taide.net>\r\n"
"\r\n"
"spam is bad do not send it"},

{0, 0, NULL}};
