<?php
class OauthApi extends Api{
	function access_token(){
		if($_REQUEST['userId'] && $_REQUEST['passwd']){
	    	$username = desdecrypt($_POST['userId'],'12345678');
	    	if( is_numeric($username) ){
	    		$map['uid'] = $username;
	    	}elseif (is_string($username)){
	    		$map['email'] = h($username);
	    	}else{
	    		return;
	    	}
	    	$map['password'] = md5(desdecrypt( h($_REQUEST['passwd']) ,'12345678' ) );
			$user = M('user')->where($map)->field('uid')->find();
			$this->mid = $user['uid'];
    	}
	}
	function request_key(){
		return array($this->getRequestKey());
	}
	private function getRequestKey(){
		return "thinksns";
	}
	public function isValidEmail($email) {
		if(UC_SYNC){
			$res = uc_user_checkemail($email);
			if($res == -4){
				return false;
			}else{
				return true;
			}
		}else{
			return preg_match("/[_a-zA-Z\d\-\.]+@[_a-zA-Z\d\-]+(\.[_a-zA-Z\d\-]+)+$/i", $email) !== 0;
		}
	}	

	
	//原来的方法
	function authorize(){
		
	}
	
	
	
	/**
	 * 帐户登录 返回Token
	 * 
	 */
	function login(){
		if($_REQUEST['user'] && $_REQUEST['passwd']){
			// 修改通过用户名和密码获得 Token
			$password = $_REQUEST['passwd'];
	    	$identifier = $_REQUEST['user'];
	    	if (empty($identifier))
	    		return false;
	    	if($this->isValidEmail($identifier)){
	    		$identifier_type = 'email';
	    	}elseif(is_numeric($identifier) && is_int($identifier)){
	    		$identifier_type = 'uid';
	    	}else{
	    		$identifier_type = 'uname';
	    	}	    	
	    	$user = D('User', 'home')->getUserByIdentifier($identifier, $identifier_type);
	    	
	    	$map['uid'] = $user['uid'];
	    	$map['password'] = md5($_REQUEST['passwd']);
	    	
			$user = M('user')->where($map)->field('uid')->find();
			if($user){
				if( $login = M('login')->where("uid=".$user['uid']." AND type='location'")->find() ){
					$data['oauth_token']         = $login['oauth_token'];
					$data['oauth_token_secret']  = $login['oauth_token_secret'];
					$data['uid']                 = $user['uid'];
				}else{
					$data['oauth_token']         = getOAuthToken($user['uid']);
					$data['oauth_token_secret']  = getOAuthTokenSecret();
					$data['uid']                 = $user['uid'];
					$savedata['type']            = 'location';
					$savedata = array_merge($savedata,$data);
					M('login')->add($savedata);
				}
				return $data;
			}else{
				$this->verifyError();
			}
    	}else{
    		$this->verifyError();
    	}
	}
	/**
	 * 帐号注销
	 * */
	function logout(){
		$user['uid'] = $_REQUEST['uid'];
		$logout = M('login')->where("uid=".$user['uid']." AND type='location'")->delete();
		return $logout;
	}
	
}