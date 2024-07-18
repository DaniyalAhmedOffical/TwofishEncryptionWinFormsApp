using System;
using System.Windows.Forms;

namespace TwofishEncryptionWinFormsApp
{
    public partial class Form1 : Form
    {
        private string keyHex = "A1AF0E74BCB0BECA048443CFD0A36D6B";

        public Form1()
        {
            InitializeComponent();
        }

        private void btnEncrypt_Click(object sender, EventArgs e)
        {
            string inputString = txtInput.Text;
            string encryptedString = TwofishEncryption.Encrypt64(inputString, keyHex);
            txtOutput.Text = encryptedString;
        }

      


        private void btnDecrypt_Click(object sender, EventArgs e)
        {
            string inputString = txtInput.Text;
            string decryptedString = TwofishEncryption.Decrypt64(inputString, keyHex);
            txtOutput.Text = decryptedString;
        }
    }
}
