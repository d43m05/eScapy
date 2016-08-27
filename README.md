# eScapy


                	       _____                                               
 	         _____  ___   / ___/  _____  ____ _    ____    __  __  _____       
	 ______ /____/ / _ \  \__ \  / ___/ / __ `/   / __ \  / / / / /____/ ______
	/_____//____/ /  __/ ___/ / / /__  / /_/ /   / /_/ / / /_/ / /____/ /_____/
        	      \___/ /____/  \___/  \__,_/   / .___/  \__, /                
                	                           /_/      /____/                 
	
usage: eScapy.py [-h] [--iPacketDelay IPACKETDELAY] [--iTOS] [--iFrag IFRAG]
                 [--cFrag] [--cfragDup] [--iFragOverlapp] [--iUrg]
                 [--iTimestamp] [--cSequence] [--cFin] [--cChecksum]
                 [--cSegmentOverlapp CSEGMENTOVERLAPP] [-ttl TTL]

optional arguments:
  -h, --help            show this help message and exit
  --iPacketDelay IPACKETDELAY
                        set packet delay value
  --iTOS                set TOS value
  --iFrag IFRAG         set fragmentation
  --cFrag               set fragmentation with chaff
  --cfragDup            set fragmentation with duplicate fragments
  --iFragOverlapp       set fragmentation with chaff and overlapping fragments
  --iUrg                set urgent pointer with chaff trailer
  --iTimestamp          skew tsval in TCP options
  --cSequence           wrap around initial sequence number
  --cFin                set Fin chaff
  --cChecksum           set checksum
  --cSegmentOverlapp CSEGMENTOVERLAPP
                        set segment Overlapp
  -ttl TTL              sets IDS ttl for chaff evasions

