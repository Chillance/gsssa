package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	sssa "github.com/SSSaaS/sssa-golang"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

type gsssa struct {
	createMin      int
	createAmount   int
	createSecret   string
	sharesFilename string
	forceOverwrite bool
	dictionary     string
}

var (
	app = kingpin.New("gsssa", "A command-line Shamir's Secret Sharing application.\nThis will generate a text file with word groups. Two rows with text next to eachother form a share. Keep these two groups together when splitting shares up!")
)

func (g *gsssa) getWordsFromDictionary() []string {

	wordsData, err := ioutil.ReadFile(g.dictionary)
	if err != nil {
		fmt.Printf("%+v\n", err)
		os.Exit(1)
	}

	words := strings.Split(string(wordsData), "\n")
	if len(words) <= 255 {
		fmt.Printf("\""+g.dictionary+"\" needs to have at least 256 words. It only has: %d\n", len(words))
		os.Exit(1)
	}

	return words
}

func (g *gsssa) encrypt() {

	if g.createMin > g.createAmount {
		fmt.Printf("Minimum can't be higher than the amount of shares created.\n")
		os.Exit(1)
	}

	if !g.forceOverwrite {
		if _, err := os.Stat(g.sharesFilename); !os.IsNotExist(err) {
			fmt.Printf("The shares file \"" + g.sharesFilename + "\" already exists. To force overwriting, use --force flag. This is done so a potential previous created shares file isn't overwritten by mistake.\n")
			os.Exit(1)
		}
	}

	wordsDictionary := g.getWordsFromDictionary()

	combined, err := sssa.Create(g.createMin, g.createAmount, g.createSecret)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	f, err := os.Create(g.sharesFilename)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	counter := 0
	for _, c := range combined {
		counter++

		count := len(c) / 44
		var buff bytes.Buffer
		comment := fmt.Sprintf("# Share %d\n", counter)
		fmt.Print(comment)
		f.WriteString(comment)

		for j := 0; j < count; j++ {
			part := c[j*44 : (j+1)*44]
			bytedata, err := base64.URLEncoding.DecodeString(part)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			buff.Write(bytedata)

			tempString := ""
			for _, b := range bytedata {
				tempString += fmt.Sprintf("%s ", strings.TrimSpace(wordsDictionary[b]))
			}
			tempString = strings.TrimSpace(tempString) + "\n"
			fmt.Print(tempString)
			f.WriteString(tempString)
		}
		fmt.Println()
		f.WriteString("\n")
	}

	comment := fmt.Sprintf("# You need %d shares out of these %d shares to be able to get your secret back.\n", g.createMin, g.createAmount)
	fmt.Print(comment)
	f.WriteString(comment)

	fmt.Printf("\n The file \"%s\" is now created with above shown information.\n\n", g.sharesFilename)

	f.Close()
}

func (g *gsssa) decrypt() {

	wordsDictionary := g.getWordsFromDictionary()

	wordsMap := make(map[string]int)
	for i, s := range wordsDictionary {
		wordsMap[s] = i
	}

	seedsData, err := ioutil.ReadFile(g.sharesFilename)
	if err != nil {
		fmt.Printf("%+v\n", err)
		os.Exit(1)
	}

	seeds := strings.Split(string(seedsData), "\n")

	var shares []string
	fullStr := ""
	for _, s := range seeds {

		if len(s) > 0 && s[0] == '#' {
			fullStr = ""
			continue
		}

		if len(s) == 0 {
			if len(fullStr) > 0 {
				shares = append(shares, fullStr)
			}
			fullStr = ""
			continue
		}

		seedWords := strings.Split(s, " ")
		var buff bytes.Buffer
		for _, w := range seedWords {
			buff.WriteByte(byte(wordsMap[w]))
		}

		fullStr += base64.URLEncoding.EncodeToString(buff.Bytes())
	}

	res, err := sssa.Combine(shares)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Printf("RESULT: %s\n", res)
}

func main() {
	g := new(gsssa)

	create := app.Command("create", "Create new Shamir's Secret Sharing strings.").Action(func(c *kingpin.ParseContext) error {
		g.encrypt()
		return nil
	})
	create.Flag("min", "Minimum shares that are needed.").Default("2").IntVar(&g.createMin)
	create.Flag("amount", "Amount of shares to generate.").Default("3").IntVar(&g.createAmount)
	create.Flag("dictionary", "The word list file. Should have at least 256 words in it. Separated by a newline. (Currently only the first 256 ones are used.)").Default("english.txt").StringVar(&g.dictionary)
	create.Flag("file", "Filename of the file containing the shares.").Short('f').Default("shares.txt").StringVar(&g.sharesFilename)
	create.Flag("force", "Overwrite file with shares.").BoolVar(&g.forceOverwrite)
	create.Arg("secret", "The secret string to hide.").Required().StringVar(&g.createSecret)

	reveal := app.Command("reveal", "Reveal secret from shares.").Action(func(c *kingpin.ParseContext) error {
		g.decrypt()
		return nil
	})

	reveal.Flag("dictionary", "The word list file. Should have at least 256 words in it. Separated by a newline. Make sure this is the same wordlist used when created the shares. (Currently only the first 256 ones are used.)").Default("english.txt").StringVar(&g.dictionary)
	reveal.Flag("file", "Filename of the file containing the shares.").Short('f').Default("shares.txt").StringVar(&g.sharesFilename)

	kingpin.MustParse(app.Parse(os.Args[1:]))
}
