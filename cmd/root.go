/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"plugin"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/trelore/pengo/scanner"
)

var cfgFile string

type Config struct {
	Plugins []string
}

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "pengo",
	Short: "A small pentesting tool",
	Run: func(cmd *cobra.Command, args []string) {
		cobra.CheckErr(run())
	},
}

func run() error {
	// todo we don't need to run these synchronously
	for _, pluginOpt := range viper.GetViper().GetStringSlice("plugins") {
		fmt.Println("Running plugin: ", pluginOpt)

		p, err := plugin.Open(filepath.Join("./plugins/", fmt.Sprintf("%s.so", pluginOpt)))
		if err != nil {
			return err
		}
		checkS, err := p.Lookup("Checker")
		if err != nil {
			return err
		}
		checker, ok := checkS.(func() scanner.Checker)
		if !ok {
			return fmt.Errorf("unexpected type from module symbol")
		}
		result := checker().Check()
		if !result.Success {
			fmt.Printf("Failed to run plugin: %s. Reason: %s", pluginOpt, result.Reason)
		}
		if result.Vulnerable {
			fmt.Println("Vulnerable: ", result.Vulnerable)
			fmt.Println("Reason: ", result.Reason)
		} else {
			fmt.Println("No vulnerabilities found")
		}
	}
	return nil
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}

func init() {
	cobra.OnInitialize(initConfig)

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.pengo.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	rootCmd.Flags().StringSliceP("plugins", "p", []string{}, "Plugins to run")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		// Search config in home directory with name ".pengo" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName(".pengo")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
}
