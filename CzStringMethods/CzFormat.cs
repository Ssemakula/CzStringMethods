namespace CzStringMethods
{
    public class CzFormat
    {
        public static string FormatNumeric(string str, char fieldType, int significance = 2)
        {
            string result = "";

            if (!string.IsNullOrEmpty(str))
            {
                string intStr = "IL";
                // 
                string value = str; //.Replace(",", "").Replace(".", "");

                //Mask
                string digitMask = "{0:#,##0";
                if (significance > 0 && !(intStr.Contains(char.ToUpper(fieldType))))
                {
                    digitMask += ".";
                    for (int x = 0; x < significance; x++)
                    {
                        digitMask += "0";
                    }
                }
                digitMask += "}";

                switch (char.ToUpper(fieldType))
                {
                    case 'D':
                        if (double.TryParse(value, out double dblNumber))
                        {
                            // Apply the formatting
                            result = string.Format(digitMask, dblNumber);
                        }
                        else
                        {
                            //currentTextBox = (TextBox)sender;
                        }
                        break;
                    case 'I':
                        if (int.TryParse(value, out int intNumber))
                        {
                            // Apply the formatting
                            result = string.Format(digitMask, intNumber);
                        }
                        else
                        {
                            //currentTextBox = (TextBox)sender;
                        }
                        break;
                    case 'L':
                        if (long.TryParse(value, out long longNumber))
                        {
                            // Apply the formatting
                            result = string.Format(digitMask, longNumber);
                        }
                        else
                        {
                            //currentTextBox = (TextBox)sender;
                        }
                        break;
                    default:
                        result = str; //Leave as it was
                        break;
                }
            }
            return result;
        }
    }
}
