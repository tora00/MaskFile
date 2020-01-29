<?php
	/**
	 * Simple program that masks sensitive data with asterisk (*).
	 * A data is considered sensitive based on words stored in keywords.
	 *
	 * @author Kevin Naval
	 */
	 
	//Global storage for sensitive data keywords
	//Add new entries here to mask and its expected length
	//To dynamically masked data, either set the value of the key to 0 or leave blank
	//Static data masking only masks up to n characters of that sensitive data
	//An example of setting a kv pair is provided in "cardnumber"
	$keywords = [
		"cardnumber" => 16,
		"account_card_number",
		"carddatanumber",
		"cardexpiry",
		"account_expiry",
		"cardexp",
		"exp",
		"cardcvv",
		"cvv",
		"cvvcvcsecurity",
	];

	/**
	*	Returns a string of asterisk with length of data passed
	*
	*	@param	string $data The sensitive data to be masked
	*	@return	string $this A string of asterisk with length of the sensitive data
	*/
	function maskData($data){
		$length = strlen($data);
		return str_pad("",$length,"*");
	}
	
	/**
	*	Finds starting index(es) that matches the keyword in a given string
	*	This function stores ALL POSSIBLE matched patterns and its index in the string
	*	Returns a 2-D array containing a data-index pair eg. $match[data][startIndex]
	*
	*	@param	string $haystack The string that contains the full input
	*	@param	string $needle The string to find inside the haystack
	*	@return	array $matches An array that contains the needles and its corresponsing index
	*/
	function findLastIndexes($haystack,$needle){
		$pattern = "/(?<![a-zA-Z0-9]|\b<\/\b)\b".$needle."\b(?![a-zA-Z0-9])/i";
		//Saves all data-index pairs of all matched patterns throughout the whole string
		if(preg_match_all($pattern,$haystack,$matches,PREG_OFFSET_CAPTURE)){
		    $mlen = count($matches[0]);
		    for($i=0; $i<$mlen; $i++){
		        //Adjust index to next index after last index of given string
				//This is used for a simpler substring operation in maskFile
		        $matches[0][$i][1] += (strlen($needle) + 1);
		    }		    
			return $matches;
		}
		else{
		    return [];
		}
	}
	
	/**
	*	Returns an array that contains 2 elements: first index of found data, and the data itself
	*	Where trimmed stack is a substring starting from the last index of the data keyword
	*	This only returns the FIRST closest entry
	*
	*	@param string $haystack The string that contains the full input
	*	@param int $startIndex The starting index, in the context of the haystack, to start looking for matching patterns
	*	@param int $lengthOfData Used for strict pattern matching. If 0, uses dynamic matching instead
	*
	*	@return array $this An array of size 2 that respectively contains the sensitive data and its index from the trimmed stack
	*/	
	function extractDataFromStack($haystack,$startIndex,$lengthOfData){
		//This regex pattern allows for alphanumeric pattern searches as well as space/dot in between alphanum
		//Strict pattern only matches a $lengthOfData number of characters
		//Dynamic and Strict patterns are chosen based on $lengthOfData value
		//This regex can also be tuned to accommodate further formatting types if needed
		//eg. 123, abc123, abc 123, 3.50
		$pattern_dynamic = "/\w+(( |\.)\w+)*/";
		$pattern_strict = "/(\w{1,".$lengthOfData."}(( |\.)\w+){0,".$lengthOfData."})/";
		$pattern = ($lengthOfData > 0)? $pattern_strict : $pattern_dynamic;
		$trimmedStack = substr($haystack,$startIndex);
		//Find and return the first occurence of matched pattern and its adjusted offset
		//Adjusted offset is relative to the whole string input, not just the trimmed haystack
		if(preg_match($pattern,$trimmedStack,$matches,PREG_OFFSET_CAPTURE)){
			return array($matches[0][0],$matches[0][1]);
		}
		else{
			return [];
		}
	}
	
	/**
	*	Entry point function
	*	Loops through each keyword to find indexes that matches the keyword
	*	Assuming there's at least 1 match, finds the closest valid pattern
	*	When a pattern is found, assume it's sensitive data and mask it
	*	The masked data replaces its non-masked version through a simple substring call
	*
	*	@param string $string The string that contains the full input
	*
	*	@return string $string A modified string of the full input that masks sensitive data based on the keyword array
	*/
	function maskFile($string){
	    global $keywords;
	    //Convert index values to key-value pair with default 0 value and remove non-kv pairs
	    $aktemp = array_keys($keywords);
	    for($i=0;$i<count($aktemp); $i++){
	        if(is_numeric($aktemp[$i])){
	            $keywords[$keywords[$aktemp[$i]]] = 0;
	            unset($keywords[$aktemp[$i]]);
	        }
	    }
		$arrayKeys = array_keys($keywords);
		$arraySize = count($arrayKeys);
		
		//Match patterns of each key in the keywords array
		for($i=0; $i<$arraySize; $i++){
			$matchesArray = findLastIndexes($string,$arrayKeys[$i]);
			if(!empty($matchesArray)){
				$maSize = count($matchesArray[0]);
				//For each entry in the matches array, find the closest valid pattern that represents the sensitive data
				for($j=0; $j<$maSize;$j++){
					$expectedDataLength = $keywords[$arrayKeys[$i]];
					if(!is_numeric($expectedDataLength))
					    $expectedDataLength = 0;
					//Extract data to an array that will contain the actual sensitive data and its index, respectively
					$sensitiveData = extractDataFromStack($string,$matchesArray[0][$j][1],$expectedDataLength);				
					//Convert found data to asterisk and save to a variable
					if(!empty($sensitiveData)){
						$maskedData = maskData($sensitiveData[0]);
						$adjustedIndex = $sensitiveData[1] + $matchesArray[0][$j][1];
						//Replaces sensitive data with the masked data on the same starting index
						$string = substr_replace($string,$maskedData,$adjustedIndex,strlen($maskedData));
					}
				}
			}
		}
		return $string;
	}
?>