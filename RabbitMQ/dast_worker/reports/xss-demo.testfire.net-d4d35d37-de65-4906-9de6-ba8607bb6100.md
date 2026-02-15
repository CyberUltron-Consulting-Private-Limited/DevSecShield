### XSS (xss) found on demo.testfire.net

----
**Details**: **xss** matched at demo.testfire.net

**Protocol**: HEADLESS

**Full URL**: 

**Timestamp**: Sun Feb 15 18:11:48 +0530 IST 2026

**Template Information**

| Key | Value |
| --- | --- |
| Name | XSS |
| Authors | pdteam |
| Tags |  |
| Severity | high |

**Response**
```http
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en"><head>
	<title>Altoro Mutual</title>
  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">
  <link href="/style.css" rel="stylesheet" type="text/css">
</head>
<body style="margin-top:5px;">

<div id="header" style="margin-bottom:5px; width: 99%;">
  <form id="frmSearch" method="get" action="/search.jsp">
	  <table width="100%" border="0" cellpadding="0" cellspacing="0">
		  <tbody><tr>
		      <td rowspan="2"><a id="HyperLink1" href="/index.jsp"><img src="/images/logo.gif" width="283" height="80/"></a></td>
			  <td align="right" valign="top">
  			  <a id="LoginLink" href="/logout.jsp"><font style="font-weight: bold; color: red;">Sign Off</font></a> | <a id="HyperLink3" href="/index.jsp?content=inside_contact.htm">Contact Us</a> | <a id="HyperLink4" href="/feedback.jsp">Feedback</a> | <label for="txtSearch">Search</label>
          <input type="text" name="query" id="query" accesskey="S">
          <input type="submit" value="Go">
			  </td>
		  </tr>
		  <tr>
			  <td align="right" style="background-image:url('/images/gradient.jpg');padding:0px;margin:0px;"><img src="/images/header_pic.jpg" alt="" width="354" height="60/"></td>
		  </tr>
	  </tbody></table>
	</form>
</div>

<div id="wrapper" style="width: 99%;">
	 

<!-- TOC BEGIN -->     
     </div><table cellspacing="0" width="100%">
  <tbody><tr>
    <td width="25%" class="bt br bb"><div id="Header1"><img id="Image1" src="/images/pf_lock.gif" width="12" height="14" style="vertical-align: bottom;" alt="Secure Login"> &nbsp; <a id="AccountLink" href="/bank/main.jsp" class="focus">MY ACCOUNT</a></div></td>
    <td width="25%" class="cc bt br bb"><div id="Header2"><a id="LinkHeader2" class="focus" href="/index.jsp?content=personal.htm">PERSONAL</a></div></td>
    <td width="25%" class="cc bt br bb"><div id="Header3"><a id="LinkHeader3" class="focus" href="/index.jsp?content=business.htm">SMALL BUSINESS</a></div></td>
    <td width="25%" class="cc bt bb"><div id="Header4"><a id="LinkHeader4" class="focus" href="/index.jsp?content=inside.htm">INSIDE ALTORO MUTUAL</a></div></td>
  </tr>
  <tr>
  
  <!-- END HEADER -->


<td valign="top" class="cc br bb">
        <br style="line-height: 10px;">
        
        <a id="CatLink1" class="subheader" href="index.jsp?content=personal.htm">PERSONAL</a>
        <ul class="sidebar">
            <li><a id="MenuHyperLink1" href="index.jsp?content=personal_deposit.htm">Deposit Product</a></li>
            <li><a id="MenuHyperLink2" href="index.jsp?content=personal_checking.htm">Checking</a></li>
            <li><a id="MenuHyperLink3" href="index.jsp?content=personal_loans.htm">Loan Products</a></li>
            <li><a id="MenuHyperLink4" href="index.jsp?content=personal_cards.htm">Cards</a></li>
            <li><a id="MenuHyperLink5" href="index.jsp?content=personal_investments.htm">Investments &amp; Insurance</a></li>
            <li><a id="MenuHyperLink6" href="index.jsp?content=personal_other.htm">Other Services</a></li>
        </ul>

        <a id="CatLink2" class="subheader" href="index.jsp?content=business.htm">SMALL BUSINESS</a>
        <ul class="sidebar">
            <li><a id="MenuHyperLink7" href="index.jsp?content=business_deposit.htm">Deposit Products</a></li>
            <li><a id="MenuHyperLink8" href="index.jsp?content=business_lending.htm">Lending Services</a></li>
            <li><a id="MenuHyperLink9" href="index.jsp?content=business_cards.htm">Cards</a></li>
            <li><a id="MenuHyperLink10" href="index.jsp?content=business_insurance.htm">Insurance</a></li>
            <li><a id="MenuHyperLink11" href="index.jsp?content=business_retirement.htm">Retirement</a></li>
            <li><a id="MenuHyperLink12" href="index.jsp?content=business_other.htm">Other Services</a></li>
        </ul>

        <a id="CatLink3" class="subheader" href="index.jsp?content=inside.htm">INSIDE ALTORO MUTUAL</a>
        <ul class="sidebar">
            <li><a id="MenuHyperLink13" href="index.jsp?content=inside_about.htm">About Us</a></li>
            <li><a id="MenuHyperLink14" href="index.jsp?content=inside_contact.htm">Contact Us</a></li>
            <li><a id="MenuHyperLink15" href="cgi.exe">Locations</a></li>
            <li><a id="MenuHyperLink16" href="index.jsp?content=inside_investor.htm">Investor Relations</a></li>
            <li><a id="MenuHyperLink17" href="index.jsp?content=inside_press.htm">Press Room</a></li>
            <li><a id="MenuHyperLink18" href="index.jsp?content=inside_careers.htm">Careers</a></li>
			<li><a id="MenuHyperLink19" href="subscribe.jsp">Subscribe</a></li>
        </ul>
    </td>
<!-- TOC END -->

    <td valign="top" colspan="3" class="bb">
		
	
		
		
		<div class="fl" style="width: 99%;">
		
		<h1>Search Results</h1>
		
		<p>No results were found for the query:<br><br>
		
		<script>alert(3+4)</script>
		
		</p></div>    
    </td>	


 

<!-- BEGIN FOOTER -->


</tr>
</tbody></table>
<div id="footer" style="width: 99%;">
    <a id="HyperLink5" href="/index.jsp?content=privacy.htm">Privacy Policy</a>
    &nbsp;&nbsp;|&nbsp;&.... Truncated ....
```

**Extra Information**

**Extracted results:**

- alert
- 7



----

Generated by [Nuclei v3.7.0](https://github.com/projectdiscovery/nuclei)