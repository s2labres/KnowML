import pandas as pd
from typing import List, Dict, Tuple
from multiprocessing import Pool

def zip_channel_dst(df: pd.DataFrame) -> pd.DataFrame:
    """
    Zip the channel and destination dataframes

    :param df: Dataframe containing the channel and destination dataframes
    :return: Dataframe containing the zipped dataframes
    """
    dst_columns = [f"{col} (dst)" for col in df.columns]

    even_rows = df.iloc[::2].reset_index(drop=True)  
    odd_rows = df.iloc[1::2].reset_index(drop=True)  

    odd_rows.columns = dst_columns

    return pd.concat([even_rows, odd_rows], axis=1)

def print_numerical_features(df: pd.DataFrame)->None:
    """
    Print the numerical columns of the dataframe
    """
    non_numerical_cols = df.select_dtypes(exclude=['int64', 'float64']).columns

    print("Non-numerical columns:")
    for col in non_numerical_cols:
        print(f"Column: {col}, Type: {df[col].dtype}")

def transform_state(df: pd.DataFrame) -> pd.DataFrame:

    df['tcp_state (dst)'] = df['tcp_state (dst)'].apply(eval)

    for i in range(7):  # for keys 0-6
        df[f'{i}_state_no'] = df['tcp_state (dst)'].apply(lambda x: x[i])

    df = df.drop('tcp_state (dst)', axis=1)

    return df

def convert_to_float(df: pd.DataFrame) -> pd.DataFrame:
    """
    Convert all columns in a DataFrame to float type.
    """
    
    for column in df.columns:
        try:
            df[column] = df[column].astype(float)
        except (ValueError, TypeError):
            print(f"Could not convert column '{column}' to float. Keeping original type.")
            
    return df
      
def process_chrollo_features(drop_columns, df):

    ml_df_chrollo = df.drop(drop_columns, axis=1)
   
    ml_df_chrollo = zip_channel_dst(ml_df_chrollo)

    ml_df_chrollo = transform_state(ml_df_chrollo)
    
    print("Before conversion:")
    print_numerical_features(ml_df_chrollo)
    print("\nAfter conversion:")
    ml_df_chrollo = convert_to_float(ml_df_chrollo)
    print_numerical_features(ml_df_chrollo)

    return ml_df_chrollo


def process_chrollo_dataset_for_ML(paths: Dict[str, str]) -> pd.DataFrame: 


    for dataset_path, save_path in paths.items():
        print(f"Processing dataset: {dataset_path}")
        chrollo_df = pd.read_csv(dataset_path, low_memory=True)
        # Process chrollo features 
        # 1. Drop identifier columns
        identifier_columns = ['src_mac', 'src_port', 'dst_mac', 'src_ip', 'dst_ip', 'dst_port']
        additonal_to_dop = [ "http_cookie_size", "http_cookie_mean", "http_cookie_std", "http_cookie_ssr"]

        # 2. Drop spurious columns - Attack might masquarade through protocol
        spurious_columns = ['protocol']
        # 3. Drop extraction (helper) features         
        drop_fe_extraction_features = ['ex_ack_number', 'ex_seq_num', 'last_ts', 'start_ts', 'receiver', "init_out_of_order", "close_out_of_order", 
                                       "last_request_ts", "last_response_ts", "start_sec", "win_start_ts", 
                                       "win_http_pks", "win_start_ts_ssh", "win_con_attempt", "win_ter_attempt"]
        

        drop_columns = identifier_columns + spurious_columns + drop_fe_extraction_features  + additonal_to_dop

        ml_df_chrollo = process_chrollo_features(drop_columns, chrollo_df)

        # 4. Drop features that are only channel level not destination level 
        drop_cols = ["min_window_size (dst)", "min_tcp_payload_size (dst)", "max_window_size (dst)", 
                     "max_tcp_payload_size (dst)", "request_interaval (dst)", "request_interval_mean (dst)", 
                     "response_interval (dst)", "response_interval_mean (dst)", "min_ttl (dst)",  
                     "max_ttl (dst)", "duration (dst)",  # There is no notion of duration for connectionless protocols hence we drop it
                     "connection_count"] # Connection is count is destination level feature only 
        
        ml_df_chrollo = ml_df_chrollo.drop(drop_cols, axis=1)

        print(f"Created dataset with shape: {ml_df_chrollo.shape}") 
        ml_df_chrollo.to_csv(save_path, index=False)
        print(f"Saved dataset to: {save_path}")


if __name__ == "__main__":
       

    paths = {
       ""
    }
    process_chrollo_dataset_for_ML(paths)