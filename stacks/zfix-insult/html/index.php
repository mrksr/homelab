<?php
// This gets nicer and nicer!
$zfix = isset($_REQUEST['z']) || isset($_REQUEST['zfix']);
$black = isset($_REQUEST['b']);
$raw = isset($_REQUEST['r']) || isset($_REQUEST['raw']);
$rawInsult = isset($_REQUEST['ri']) || isset($_REQUEST['rawinsult']);
$tobi = isset($_REQUEST['t']);

if ($tobi) {
    $out = "<img src='_it.png'>";
} else {
    if (!$zfix && !$black) {
        $lines = file("_insults");
        $rawline = trim($lines[array_rand($lines)]);
        preg_match('/([^=\n]+)(?:=(.+))?/', $rawline, $matches);

        $title = isset($matches[2]) ? $matches[2] : '';
        $insult = preg_match('/[!?.]$/', $matches[1]) > 0
            ? $matches[1]
            : $matches[1].'!';
    } else if ($black) {
        $insult = '';
        $title = '?';
    } else {
        $insult = 'zﬁx.';
        $title = '!';
    }

    $out = "<div title='$title'><a class='zfix' href='.'>$insult</a></div>\n";
}

if ($raw && !$tobi && !$black) {
    echo $insult.'='.$title."\n";
} elseif ($rawInsult && !$tobi && !$black) {
    echo $insult."\n";
} else {
?>
<!DOCTYPE html>
<html>
    <head>
        <!--
        Hello there! So you have found the surprisingly discoverable API
        "documentation", congratulations!

        You might want to try the following URLs:
            - https://zfix.org?r
            - https://zfix.org?ri
            - https://zfix.org?z
        -->
        <link rel="icon" href="/zfix_1024.png">
        <title><?=$_SERVER["HTTP_HOST"]?></title>
        <style type="text/css">
            html, body {
                width: 100%;
                height: 100%;
                margin: 0;
                padding: 0;

                background-color: #DFE6E1;
            }

            a {
                font-size: 250%;
                font-family: Serif;
                text-decoration: none;
                color: #0B5926;
            }

            .zfix {
                font-size: 666%;
            }

            .centered {
                width: 100%;
                height: 100%;

                text-align: center;

                display: flex;
                flex-direction: column;
                align-items: center;
                justify-content: center;
            }
        </style>
    </head>
    <body>
        <div class='centered'>
            <?=$out?>
            <div><a href='https://zfix.org'>z</a>&nbsp;&nbsp;<a href='https://dash.zfix.org'>d</a>&nbsp;&nbsp;<a href='https://mrksr.de'>m</a></div>
            <div><a style='font-size: 125%' href='https://zfix.org/impressum.htm'>Impressum</a></div>
        </div>
    </body>
</html>
<?php
}
?>
