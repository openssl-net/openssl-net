// Copyright (c) 2012 Frank Laub
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
// 3. The name of the author may not be used to endorse or promote products
//    derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
// OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
// IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
// NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
// THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

using System;
using NUnit.Framework;
using OpenSSL.Core;
using Random = OpenSSL.Core.Random;
using System.Runtime.InteropServices;
using OpenSSL.Crypto;
using System.Text;

namespace UnitTests.OpenSSL
{
	[TestFixture]
	public class ECDSATest : BaseTest
	{
		private void x9_62_test_internal(Asn1Object obj, string r_in, string s_in) {
			byte[] message = Encoding.ASCII.GetBytes("abc");
			
			using(MessageDigestContext md_ctx = new MessageDigestContext(MessageDigest.ECDSA)) {
				byte[] digest = md_ctx.Digest(message);
				
				Console.Write("testing {0}: ", obj.ShortName);
	
				using(ECKey key = ECKey.FromCurveName(obj)) {
					key.GenerateKey();
					Console.Write(".");
					using(ECDSASignature signature = key.Sign(digest)) {
						Console.Write(".");
						BigNumber r = BigNumber.FromDecimalString(r_in);
						BigNumber s = BigNumber.FromDecimalString(s_in);
						Assert.AreEqual(r, signature.R);
						Assert.AreEqual(s, signature.S);
						Console.Write(".");
						Assert.IsTrue(key.Verify(digest, signature));
						Console.Write(".");
					}
				}
			}
			Console.WriteLine(" ok");
		}
		
		[Test]
		public void x9_62_tests() {
			Random.Seed("string to make the random number generator think it has entropy");

			Console.WriteLine("some tests from X9.62");
			
			using(Random.Method meth = new Random.Method()) {
				//meth.PseudoRand = meth.Bytes;
				//meth.Bytes = this.fbytes;
				//meth.Override();
				
				x9_62_test_internal(Objects.NID.X9_62_prime192v1, 
				                    "3342403536405981729393488334694600415596881826869351677613", 
				                    "5735822328888155254683894997897571951568553642892029982342");
				x9_62_test_internal(Objects.NID.X9_62_prime239v1, 
				                    "308636143175167811492622547300668018854959378758531778147462058306432176", 
				                    "323813553209797357708078776831250505931891051755007842781978505179448783");
				x9_62_test_internal(Objects.NID.X9_62_c2tnb191v1, 
				                    "87194383164871543355722284926904419997237591535066528048", 
				                    "308992691965804947361541664549085895292153777025772063598");
				x9_62_test_internal(Objects.NID.X9_62_c2tnb239v1, 
				                    "21596333210419611985018340039034612628818151486841789642455876922391552", 
				                    "197030374000731686738334997654997227052849804072198819102649413465737174");
			}
		}

		[Test]
		public void test_builtin() {
		}
		
		private int fbytes(byte[] buf, int num) {
			if (fbytes_counter >= 8)
				return 0;
			
			using(BigNumber tmp = BigNumber.FromDecimalString(numbers[fbytes_counter])) {
				fbytes_counter++;
				if (num != tmp.Bytes)
					return 0;
				tmp.ToBytes(buf);
			}
			
			return 1;
		}
		
		private int fbytes_counter = 0;
		private string[] numbers = {
			"651056770906015076056810763456358567190100156695615665659",
			"6140507067065001063065065565667405560006161556565665656654",
			"876300101507107567501066130761671078357010671067781776716671676178726717",
			"700000017569056646655505781757157107570501575775705779575555657156756655",
			"1275552191113212300012030439187146164646146646466749494799",
			"1542725565216523985789236956265265265235675811949404040041",
			"145642755521911534651321230007534120304391871461646461466464667494947990",
			"171278725565216523967285789236956265265265235675811949404040041670216363"
		};
	}
}

