a = b('ola');
c = d('oi');
i = "";
while (a != "") {
    f = s(c, 0, 1);

    if (f == "a") {
        i = i + "'";
    }
    else {
        i = i + " ";
    }
    a = s(a, 1);
}
z(0, i);

// tip: implicit flows can come from any of the nested conditions/loops
/*
a -> A: (b,1)
c-> A: ; B: (d,2)

WHILE 1
implicit while: a -> A: (b,1)

f -> A: (d,2) [s,5]; (b,1) [s,5]

IF 1
implicit if: f -> A: (d,2) [s,5]; (b,1) [s,5]

i -> A: (b,1) [s,5]; (d,2) [s,5]
END IF 1

a -> (b,1) [s,13]; 

END WHILE 1
WHILE 2
implicit while: a -> A: (b,1), [s,13]
f -> A: (d,2) [s,5]; (b,1) [[s,13], [s,5]], [s,13]

IF 2
implicit if: f -> A: (d,2) [s,5]; (b,1) [[s,13], [s,5]], [s,13]



*/