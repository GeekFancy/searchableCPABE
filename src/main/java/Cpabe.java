import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.ArrayList;

import java.util.List;

public class Cpabe {
    private CpabePub pub;

    private CpabeMsk msk;

    private String[][] attr;  //属性全集（分类后）

    private int attr_num;

    private int attr_total_num;

    private List<Integer> attr_list_num;  //每种子属性集所含属性个数

    private Pairing pairing;

    private CpabeCph cph;

    private CpabeKey ckey;

    private Element m;  //明文

    public Element hash(Pairing pairing,String att){
        byte[] attr = att.getBytes();
        Element Hash = pairing.getZr().newElement().setFromHash(attr,0,attr.length);
        return Hash;
    }
    public int getIndex(int x,int y){
        int index = 0 ;
        for(int i = 0 ; i<x;i++){
            index = index + attr_list_num.get(i);
        }
        index = index + y;
        return index;
    }  //计算属性位置

    public void setupAttr(String[][] attr){
        this.attr = attr;
        this.attr_num = attr.length;
        for(int i = 0;i<attr.length;i++){
            this.attr_list_num.add(attr[i].length);
        }
        int tmp = 0;
        for(int i = 0;i<attr_list_num.size();i++){
            tmp = tmp + attr_list_num.get(i);
        }
        this.attr_total_num = tmp;
    }

    public void Setup(String properties,String[][] att){
        pairing = PairingFactory.getPairing(properties);
        attr_list_num = new ArrayList<Integer>();
        setupAttr(att);
        pub = new CpabePub();
        msk = new CpabeMsk();
        Element g = pairing.getG2().newRandomElement().getImmutable();
        Element y = pairing.getZr().newRandomElement().getImmutable();
        Element g_y = g.powZn(y);
        Element Y = pairing.pairing(g,g_y);
        pub.g = g;
        pub.Y = Y;
        msk.y = y;
        msk.a = new ArrayList<Element>();
        pub.A = new ArrayList<Element>();
        for(int i = 0;i<attr_num;i++){
            for(int j = 0;j<attr_list_num.get(i);j++){
                Element tmp = pairing.getZr().newRandomElement().getImmutable();
                msk.a.add(tmp);
                pub.A.add(g.powZn(tmp));
            }
        }
    }

    public String[] divideAttr(String att){
        String[] ans = att.split("\\s+");
        return ans;
    }  //将用户属性集分成属性

    public Element attrMul(String[] att){
        Element ans = pairing.getG2().newElement().setToOne();
        int[] index = new int[attr_num];
        for(int i = 0; i<attr_num;i++){
            for(int j = 0;j<attr_list_num.get(i);j++){
                if(att[i].equals(attr[i][j])){
                    index[i] = getIndex(i,j);
                    ans = ans.mul(pub.A.get(index[i]));
                }
            }
        }
        return  ans;
    }  //计算A积, attr是用户每个属性组成的集合

    public Element attrPlus(String[] att){
        Element ans = pairing.getZr().newElement().setToZero();
        int[] index = new int[attr_num];
        for(int i = 0; i<attr_num;i++){
            for(int j = 0;j<attr_list_num.get(i);j++){
                if(att[i].equals(attr[i][j])){
                    index[i] = getIndex(i,j);
                    ans = ans.add(msk.a.get(index[i]));
                }
            }
        }
        return  ans;
    }  //计算a和

    public void Encrypt(String[] rt){
        cph = new CpabeCph();
        cph.c_rt = new ArrayList<Element>();
        cph.c_rt_h = new ArrayList<Element>();
        Element s = pairing.getZr().newRandomElement().getImmutable();
        m = pairing.getGT().newRandomElement().getImmutable();
        cph.c_hat = m.mul(pub.Y.powZn(s));
        cph.c_hatm = pub.g.powZn(s);
        for(int i = 0;i<rt.length;i++){
            String tmp = rt[i];
            String[] att = divideAttr(tmp);
            Element c_rt = attrMul(att).powZn(s);
            Element c_rt_h = hash(pairing,rt[i]); //还没写如何hash ,这行重写
            cph.c_rt.add(c_rt);
            cph.c_rt_h.add(c_rt_h);
        }
    }

    public void KeyGen(String att){
        ckey = new CpabeKey();
        Element r = pairing.getZr().newRandomElement().getImmutable();
        Element sum = attrPlus(divideAttr(att));
        ckey.d = pub.g.powZn(r.div(sum));
        ckey.d_hat = pub.g.powZn(msk.y.sub(r));
        ckey.d_hash = hash(pairing,att);
    }

    public void Decrypt(){
        int index = 0;
        boolean acc = false;
        for(;index<cph.c_rt_h.size();index++){
            if(cph.c_rt_h.get(index).isEqual(ckey.d_hash)){
                acc = true;
                break;
            }
        }
        if(acc) {
            Element p1 = pairing.pairing(cph.c_hatm, ckey.d_hat);
            Element p2 = pairing.pairing(cph.c_rt.get(index), ckey.d);
            Element m_dec = cph.c_hat.div(p1.mul(p2));
            System.out.println("Decrypt Successfully!The plaintext is:"+m_dec);
        }
        else {
            System.out.println("Decrypt Failed");
        }
    }

    public void Print(){
        int pos = 0;
        System.out.println(attr_num);
        System.out.println(attr_total_num);
        for(int i = 0;i<attr_num;i++){
            for(int j = 0;j<attr_list_num.get(i);j++){
                System.out.println( i+ "  "+j+"a:" + msk.a.get(pos));
                System.out.println( i+ "  "+j+"A:" + pub.A.get(pos));
                pos++;
            }
        }
        for(int i = 0;i<cph.c_rt.size();i++){
            System.out.println(cph.c_rt.get(i));
        }
        System.out.println(ckey.d);

        System.out.println("Test");
        System.out.println("The input plaintext is:"+m);
//        Element test_zr1 = pairing.getZr().newRandomElement().getImmutable();
//        Element test_zr2 = pairing.getZr().newRandomElement().getImmutable();
//        Element test_g1 = pub.g.powZn(test_zr1);
//        Element test_g2 = pub.g.powZn(test_zr2);
//        Element mul = test_g1.mul(test_g2);
//        Element sum = pub.g.powZn(test_zr1.add(test_zr2));
//        System.out.println(mul);
//        System.out.println(sum);
//        System.out.println(mul.isEqual(sum));
    }
    public static void main(String[] args) {
        long startTime = System.currentTimeMillis();
        for(int i = 0 ;i<100;i++){
            Cpabe cpabe = new Cpabe();
            String[][] att = {{"Abb","Acc"},{"Bcc","Bdd","Bee"},{"Cdd","Cee","Cff","Cgg"},{"Dee","Dff"}};
            String[] rt = {"Abb Bcc Cdd Dee","Acc Bdd Cee Dff"};
            String att_user = "Acc Bdd Cee Dff";
            cpabe.Setup("a.properties",att);
            cpabe.Encrypt(rt);
            cpabe.KeyGen(att_user);
//            cpabe.Print();
            cpabe.Decrypt();
        }

        long endTime = System.currentTimeMillis();
        System.out.println("程序运行时间：" + (endTime - startTime) + "ms");
        Cpabe cpabe = new Cpabe();
        String[][] att = {{"Abb","Acc"},{"Bcc","Bdd","Bee"},{"Cdd","Cee","Cff","Cgg"},{"Dee","Dff"}};
        String[] rt = {"Abb Bcc Cdd Dee","Acc Bdd Cee Dff"};

        String att_user = "Acc Bdd Cee Dff";
        cpabe.Setup("a.properties",att);
        cpabe.Encrypt(rt);
        cpabe.KeyGen(att_user);
        cpabe.Print();
        cpabe.Decrypt();
    }
}