using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CzStringMethods
{
    public class CzRandString
    {
        /// <summary>
        /// Generates a human readeable hex no of length strlength
        /// </summary>
        /// <param name="strLength">Required string length</param>
        /// <param name="useless"></param>
        /// <returns>human readeable hex no</returns>
        public static string GenerateRandomString(int strLength, Boolean useless = true) //Removes the place, not really for anuthing
        {
            // Get the current datetime as a seed
            long seed = DateTime.Now.Ticks;
            string randomHexString;

            // Initialize a random number generator with the seed
            Random random = new((int)(seed & 0xFFFFFFFFL) | (int)(seed >> 32));

            // Create a byte array to store the random bytes
            byte[] randomBytes = new byte[strLength];

            // Generate random bytes
            random.NextBytes(randomBytes);

            // Convert the byte array to a hexadecimal string
            if (useless)
            {
                randomHexString = BitConverter.ToString(randomBytes).Replace("-", "");
            }
            else
            {
                randomHexString = BitConverter.ToString(randomBytes); //.Replace("-", ""); //This is the difference
            }


            return randomHexString;
        }
    }
}
